package javadisk

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

type taint uint16

const (
	taintRequestParameter taint = 1 << iota
	taintRequestHeader
	taintRequestBody
	taintCookie
	taintSession
	taintApplication
)

type valueKind uint16

const (
	kindUnknown valueKind = 1 << iota
	kindString
	kindBytes
	kindPath
	kindClassBytes
	kindScript
	kindProcess
)

type verifierType uint8

const (
	verifierTop verifierType = iota
	verifierInt
	verifierFloat
	verifierLong
	verifierDouble
	verifierReference
	verifierNull
	verifierReturnAddress
	verifierUninitialized
)

type referenceNullness uint8

const (
	nullnessUnknown referenceNullness = iota
	nullnessNull
	nullnessNonNull
)

type provenanceStep struct {
	Offset uint32
	API    string
}

type abstractValue struct {
	Taint       taint
	Arguments   argumentSet
	Kinds       valueKind
	Constant    string
	Provenance  []provenanceStep
	ObjectID    uint32
	ObjectIDs   []uint32
	Verifier    verifierType
	Reference   string
	RuntimeType string
	Nullness    referenceNullness
	ArrayLength int64
	LengthKnown bool
	SummaryOnly bool
	Width       uint8
}

type instructionExceptions struct {
	Types            []string
	Unknown          bool
	DefinitelyAbrupt bool
	Unproven         bool
}

type fieldKey struct {
	ObjectID                uint32
	Owner, Name, Descriptor string
	ArrayIndex              int64
	ArrayIndexKnown         bool
}

type frame struct {
	Locals, Stack []abstractValue
	Fields        map[fieldKey]abstractValue
	Heap          map[uint32]heapObject
	Unproven      bool
	ThisUninit    bool
}

type lambdaValue struct {
	Target   memberReference
	Captured []abstractValue
}

type heapEntry struct {
	Key      string
	KeyKnown bool
	Value    abstractValue
}

type heapObject struct {
	Builder abstractValue
	Stream  abstractValue
	Lambda  []lambdaValue
	List    []abstractValue
	Map     []heapEntry
}

type stateWorkItem struct {
	Block uint32
	Index int
}

type stateWorkQueue struct {
	items []stateWorkItem
}

func (q *stateWorkQueue) len() int { return len(q.items) }

func stateWorkLess(left, right stateWorkItem) bool {
	if left.Block != right.Block {
		return left.Block < right.Block
	}
	return left.Index < right.Index
}

func (q *stateWorkQueue) push(ctx context.Context, item stateWorkItem, budget *abstractBudget) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := budget.charge("worklist retained entry", 1); err != nil {
		return err
	}
	q.items = append(q.items, item)
	for index := len(q.items) - 1; index > 0; {
		if err := ctx.Err(); err != nil {
			return err
		}
		parent := (index - 1) / 2
		if err := budget.charge("worklist heap comparison", 1); err != nil {
			return err
		}
		if !stateWorkLess(q.items[index], q.items[parent]) {
			break
		}
		if err := budget.charge("worklist heap swap", 1); err != nil {
			return err
		}
		q.items[index], q.items[parent] = q.items[parent], q.items[index]
		index = parent
	}
	return nil
}

func (q *stateWorkQueue) pop(ctx context.Context, budget *abstractBudget) (stateWorkItem, error) {
	if err := ctx.Err(); err != nil {
		return stateWorkItem{}, err
	}
	if len(q.items) == 0 {
		return stateWorkItem{}, fmt.Errorf("empty abstract worklist")
	}
	if err := budget.charge("worklist removal", 1); err != nil {
		return stateWorkItem{}, err
	}
	result := q.items[0]
	last := q.items[len(q.items)-1]
	q.items = q.items[:len(q.items)-1]
	if len(q.items) == 0 {
		return result, nil
	}
	q.items[0] = last
	for index := 0; ; {
		if err := ctx.Err(); err != nil {
			return stateWorkItem{}, err
		}
		left := index*2 + 1
		if left >= len(q.items) {
			break
		}
		smallest := left
		right := left + 1
		if right < len(q.items) {
			if err := budget.charge("worklist heap comparison", 1); err != nil {
				return stateWorkItem{}, err
			}
			if stateWorkLess(q.items[right], q.items[left]) {
				smallest = right
			}
		}
		if err := budget.charge("worklist heap comparison", 1); err != nil {
			return stateWorkItem{}, err
		}
		if !stateWorkLess(q.items[smallest], q.items[index]) {
			break
		}
		if err := budget.charge("worklist heap swap", 1); err != nil {
			return stateWorkItem{}, err
		}
		q.items[index], q.items[smallest] = q.items[smallest], q.items[index]
		index = smallest
	}
	return result, nil
}

type handlerIntervalNode struct {
	handler indexedExceptionHandler
	maxEnd  uint32
	left    *handlerIntervalNode
	right   *handlerIntervalNode
}

type indexedExceptionHandler struct {
	exceptionHandler
	order int
}

type handlerIntervalIndex struct {
	root *handlerIntervalNode
}

func newHandlerIntervalIndex(ctx context.Context, handlers []exceptionHandler, budget *abstractBudget) (*handlerIntervalIndex, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(handlers) == 0 {
		return &handlerIntervalIndex{}, nil
	}
	if err := budget.charge("handler interval retained nodes", len(handlers)); err != nil {
		return nil, err
	}
	if err := budget.charge("handler interval ordered buffer", len(handlers)); err != nil {
		return nil, err
	}
	if err := budget.charge("handler interval merge buffer", len(handlers)); err != nil {
		return nil, err
	}
	for width := 1; width < len(handlers); {
		for pass := 0; pass < 3; pass++ {
			if err := budget.charge("handler interval sort upper bound", len(handlers)); err != nil {
				return nil, err
			}
		}
		if width > len(handlers)/2 {
			break
		}
		width *= 2
	}
	ordered, err := sortExceptionHandlersContext(ctx, handlers)
	if err != nil {
		return nil, err
	}
	built := 0
	var build func(int, int) (*handlerIntervalNode, error)
	build = func(start, end int) (*handlerIntervalNode, error) {
		if start >= end {
			return nil, nil
		}
		if built%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		built++
		middle := start + (end-start)/2
		node := &handlerIntervalNode{handler: ordered[middle], maxEnd: ordered[middle].End}
		node.left, err = build(start, middle)
		if err != nil {
			return nil, err
		}
		node.right, err = build(middle+1, end)
		if err != nil {
			return nil, err
		}
		if node.left != nil && node.left.maxEnd > node.maxEnd {
			node.maxEnd = node.left.maxEnd
		}
		if node.right != nil && node.right.maxEnd > node.maxEnd {
			node.maxEnd = node.right.maxEnd
		}
		return node, nil
	}
	root, err := build(0, len(ordered))
	if err != nil {
		return nil, err
	}
	return &handlerIntervalIndex{root: root}, nil
}

func sortExceptionHandlersContext(ctx context.Context, handlers []exceptionHandler) ([]indexedExceptionHandler, error) {
	ordered := make([]indexedExceptionHandler, len(handlers))
	for index := range handlers {
		if index%256 == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		ordered[index] = indexedExceptionHandler{exceptionHandler: handlers[index], order: index}
	}
	temporary := make([]indexedExceptionHandler, len(handlers))
	source, target := ordered, temporary
	operations := 0
	for width := 1; width < len(handlers); {
		for start := 0; start < len(handlers); start += width * 2 {
			middle := start + width
			if middle > len(handlers) {
				middle = len(handlers)
			}
			end := middle + width
			if end > len(handlers) {
				end = len(handlers)
			}
			left, right := start, middle
			for output := start; output < end; output++ {
				if operations%256 == 0 {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
				}
				operations++
				if left < middle && (right >= end || exceptionHandlerLess(source[left], source[right])) {
					target[output] = source[left]
					left++
				} else {
					target[output] = source[right]
					right++
				}
			}
		}
		source, target = target, source
		if width > len(handlers)/2 {
			break
		}
		width *= 2
	}
	if len(handlers) > 1 && &source[0] != &ordered[0] {
		copy(ordered, source)
	}
	return ordered, nil
}

func exceptionHandlerLess(left, right indexedExceptionHandler) bool {
	if left.Start != right.Start {
		return left.Start < right.Start
	}
	if left.End != right.End {
		return left.End < right.End
	}
	if left.Handler != right.Handler {
		return left.Handler < right.Handler
	}
	if left.CatchType != right.CatchType {
		return left.CatchType < right.CatchType
	}
	return left.order < right.order
}

func (index *handlerIntervalIndex) applicable(ctx context.Context, offset uint32, budget *abstractBudget) ([]exceptionHandler, error) {
	matches := []indexedExceptionHandler(nil)
	var visit func(*handlerIntervalNode) error
	visit = func(node *handlerIntervalNode) error {
		if node == nil {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := budget.charge("handler interval query", 1); err != nil {
			return err
		}
		if node.left != nil && node.left.maxEnd > offset {
			if err := visit(node.left); err != nil {
				return err
			}
		}
		if node.handler.Start <= offset && offset < node.handler.End {
			if err := budget.charge("applicable handler retention", 1); err != nil {
				return err
			}
			matches = append(matches, node.handler)
		}
		if node.handler.Start <= offset {
			return visit(node.right)
		}
		return nil
	}
	if err := visit(index.root); err != nil {
		return nil, err
	}
	if err := budget.charge("applicable handler order", len(matches)); err != nil {
		return nil, err
	}
	for width := 1; width < len(matches); width *= 2 {
		if err := budget.charge("applicable handler sort", len(matches)); err != nil {
			return nil, err
		}
		if width > len(matches)/2 {
			break
		}
	}
	sort.Slice(matches, func(i, j int) bool { return matches[i].order < matches[j].order })
	result := make([]exceptionHandler, len(matches))
	for matchIndex := range matches {
		result[matchIndex] = matches[matchIndex].exceptionHandler
	}
	return result, nil
}

type methodAnalysis struct {
	RequestExec     bool
	Evidence        []provenanceStep
	Source          provenanceStep
	Sink            provenanceStep
	SinkResults     []sinkResult
	Frames          map[uint32]frame
	Unsupported     string
	BudgetExhausted string
	Cancelled       bool
	StackMapInvalid bool
	VerifierInvalid bool
	WorkUnits       int
	Summary         methodSummary
	summaries       summarySet
	summarizing     bool
	returnSeen      bool
}

type sinkResult struct {
	Kind     sinkKind
	Score    int
	Evidence []provenanceStep
	Source   provenanceStep
	Sink     provenanceStep
}

type abstractBudget struct {
	limit int
	used  int
	ctx   context.Context
}

type abstractBudgetError struct {
	detail string
}

func (e *abstractBudgetError) Error() string { return e.detail }

type noNormalFlowError struct{}

func (*noNormalFlowError) Error() string { return "instruction has no normal successor" }

type unsupportedBytecodeError struct{ detail string }

func (e *unsupportedBytecodeError) Error() string { return e.detail }

func (b *abstractBudget) charge(component string, units int) error {
	if b.ctx != nil {
		if err := b.ctx.Err(); err != nil {
			return err
		}
	}
	if units < 0 || units > b.limit-b.used {
		return &abstractBudgetError{detail: fmt.Sprintf(
			"abstract state/work limit %d exceeded before %s (%d used, %d requested)",
			b.limit, component, b.used, units,
		)}
	}
	b.used += units
	return nil
}

func (b *abstractBudget) chargeValueCopies(component string, base int, values []abstractValue, copies int) error {
	if b.ctx != nil {
		if err := b.ctx.Err(); err != nil {
			return err
		}
	}
	remaining := b.limit - b.used
	if base < 0 || copies < 0 || base > remaining {
		return b.exhausted(component, base)
	}
	total := base
	for copyIndex := 0; copyIndex < copies; copyIndex++ {
		for _, value := range values {
			units := 1
			for _, length := range []int{len(value.Provenance), len(value.ObjectIDs)} {
				if length < 0 || length > remaining-total {
					return b.exhausted(component, remaining+1)
				}
				total += length
			}
			if units > remaining-total {
				return b.exhausted(component, remaining+1)
			}
			total += units
		}
	}
	b.used += total
	return nil
}

func (b *abstractBudget) exhausted(component string, requested int) error {
	return &abstractBudgetError{detail: fmt.Sprintf(
		"abstract state/work limit %d exceeded before %s (%d used, %d requested)",
		b.limit, component, b.used, requested,
	)}
}

const (
	staticObjectID   uint32 = 0
	receiverObjectID        = math.MaxUint32
)

var requestParameterTypes = map[string]struct{}{
	"javax/servlet/ServletRequest": {}, "javax/servlet/http/HttpServletRequest": {},
	"jakarta/servlet/ServletRequest": {}, "jakarta/servlet/http/HttpServletRequest": {},
}

func analyzeMethod(cf *classModel, method *methodModel, cfg *controlFlowGraph, opts Options, summaries summarySet) methodAnalysis {
	return analyzeMethodContext(context.Background(), cf, method, cfg, opts, summaries)
}

func analyzeMethodContext(
	ctx context.Context,
	cf *classModel,
	method *methodModel,
	cfg *controlFlowGraph,
	opts Options,
	sets ...summarySet,
) (result methodAnalysis) {
	var summaries summarySet
	if len(sets) != 0 {
		summaries = sets[0]
	}
	return analyzeMethodInternal(ctx, cf, method, cfg, opts, summaries, false)
}

func analyzeMethodSummaryContext(
	ctx context.Context,
	cf *classModel,
	method *methodModel,
	cfg *controlFlowGraph,
	opts Options,
	summaries summarySet,
) methodAnalysis {
	return analyzeMethodInternal(ctx, cf, method, cfg, opts, summaries, true)
}

func analyzeMethodInternal(
	ctx context.Context,
	cf *classModel,
	method *methodModel,
	cfg *controlFlowGraph,
	opts Options,
	summaries summarySet,
	summarizing bool,
) (result methodAnalysis) {
	opts = normalizeOptions(opts)
	if ctx == nil {
		ctx = context.Background()
	}
	budget := &abstractBudget{limit: opts.Limits.MaxStateMerges, ctx: ctx}
	result.summaries = summaries
	result.summarizing = summarizing
	result.Summary = emptyMethodSummary()
	defer func() {
		result.WorkUnits = budget.used
		if result.Unsupported != "" || result.BudgetExhausted != "" || result.Cancelled {
			clearMethodExecution(&result)
		}
	}()
	if ctx.Err() != nil {
		result.Cancelled = true
		return result
	}
	if cf == nil || method == nil || method.Code == nil || cfg == nil {
		result.Unsupported = "missing class, method, code, or control-flow graph"
		return result
	}
	code := method.Code
	if int(code.MaxLocals)+int(code.MaxStack) > opts.Limits.MaxFrameSlots {
		result.BudgetExhausted = fmt.Sprintf("frame slots %d exceed limit %d", int(code.MaxLocals)+int(code.MaxStack), opts.Limits.MaxFrameSlots)
		return result
	}
	descriptor, err := parseMethodDescriptor(method.Descriptor)
	if err != nil {
		result.Unsupported = "invalid method descriptor: " + err.Error()
		result.VerifierInvalid = true
		return result
	}
	if method.Access&0x0008 == 0 && descriptor.ParameterSlots+1 > maxJVMParameterSlots {
		result.Unsupported = fmt.Sprintf("receiver and parameter slots exceed JVM limit %d", maxJVMParameterSlots)
		result.VerifierInvalid = true
		return result
	}
	if err := validateHandlerCatchTypes(code.Handlers, budget); err != nil {
		setMethodAnalysisError(&result, err)
		if result.Unsupported != "" {
			result.VerifierInvalid = true
		}
		return result
	}
	stackMaps, err := validateStackMapStructure(cf, method, cfg, budget)
	if err != nil {
		setMethodAnalysisError(&result, err)
		if result.Unsupported != "" {
			result.StackMapInvalid = true
			result.VerifierInvalid = true
		}
		return result
	}
	handlerIndex, err := newHandlerIntervalIndex(ctx, code.Handlers, budget)
	if err != nil {
		if err == context.Canceled {
			markMethodCancelled(&result)
		} else {
			setMethodAnalysisError(&result, err)
		}
		return result
	}
	entry, err := initialFrame(cf, method, descriptor, opts, budget, summarizing)
	if err != nil {
		setMethodAnalysisError(&result, err)
		if result.BudgetExhausted == "" {
			result.VerifierInvalid = true
		}
		return result
	}
	if len(cfg.Blocks) == 0 {
		return result
	}
	if cfg.Blocks[cfg.Entry] == nil {
		result.Unsupported = "CFG entry does not name a block"
		result.VerifierInvalid = true
		return result
	}
	if err := budget.charge("entry frame map", 1); err != nil {
		setMethodAnalysisError(&result, err)
		return result
	}
	result.Frames = make(map[uint32]frame)
	result.Frames[cfg.Entry] = entry
	states := map[uint32][]frame{cfg.Entry: {entry}}
	worklist := stateWorkQueue{}
	if err := worklist.push(ctx, stateWorkItem{Block: cfg.Entry}, budget); err != nil {
		setMethodAnalysisError(&result, err)
		return result
	}

	mergeInto := func(target uint32, incoming frame) bool {
		if ctx.Err() != nil {
			markMethodCancelled(&result)
			return false
		}
		if declared, ok := stackMaps[target]; ok {
			if frameErr := validateFrameAgainstStackMap(cf, incoming, declared, budget); frameErr != nil {
				if errors.Is(frameErr, context.Canceled) {
					markMethodCancelled(&result)
					return false
				}
				if _, ok := frameErr.(*abstractBudgetError); ok {
					setMethodAnalysisError(&result, frameErr)
					return false
				}
				result.Unsupported = fmt.Sprintf("block %d StackMapTable frame: %v", target, frameErr)
				result.StackMapInvalid = true
				result.VerifierInvalid = true
				return false
			}
		}
		alternatives := states[target]
		for _, existing := range alternatives {
			equal, equalErr := framesEqualBudget(existing, incoming, budget)
			if equalErr != nil {
				setMethodAnalysisError(&result, equalErr)
				return false
			}
			if equal {
				return true
			}
		}
		if len(alternatives) >= frameAlternativeLimit(opts.Limits) {
			setMethodAnalysisError(&result, &abstractBudgetError{detail: fmt.Sprintf(
				"block %d frame alternatives exceed limit %d", target, frameAlternativeLimit(opts.Limits),
			)})
			return false
		}
		retained, cloneErr := cloneFrameBudget(incoming, budget, "successor frame alternative retention")
		if cloneErr != nil {
			setMethodAnalysisError(&result, cloneErr)
			return false
		}
		if len(alternatives) == 0 {
			result.Frames[target] = retained
		} else {
			merged, _, mergeErr := mergeFrames(result.Frames[target], retained, opts.Limits, budget)
			if mergeErr != nil {
				if _, ok := mergeErr.(*abstractBudgetError); ok {
					setMethodAnalysisError(&result, mergeErr)
				} else {
					result.Unsupported = fmt.Sprintf("block %d merge: %v", target, mergeErr)
					result.VerifierInvalid = true
				}
				return false
			}
			result.Frames[target] = merged
		}
		states[target] = append(alternatives, retained)
		if pushErr := worklist.push(ctx, stateWorkItem{Block: target, Index: len(alternatives)}, budget); pushErr != nil {
			if pushErr == context.Canceled {
				markMethodCancelled(&result)
			} else {
				setMethodAnalysisError(&result, pushErr)
			}
			return false
		}
		return true
	}

	for worklist.len() != 0 && result.Unsupported == "" && result.BudgetExhausted == "" && !result.Cancelled {
		if ctx.Err() != nil {
			markMethodCancelled(&result)
			break
		}
		item, popErr := worklist.pop(ctx, budget)
		if popErr != nil {
			if popErr == context.Canceled {
				markMethodCancelled(&result)
			} else {
				setMethodAnalysisError(&result, popErr)
			}
			break
		}
		start := item.Block
		block := cfg.Blocks[start]
		if block == nil {
			result.Unsupported = fmt.Sprintf("missing block %d", start)
			result.VerifierInvalid = true
			break
		}
		if item.Index < 0 || item.Index >= len(states[start]) {
			result.Unsupported = fmt.Sprintf("missing block %d frame alternative %d", start, item.Index)
			result.VerifierInvalid = true
			break
		}
		current, cloneErr := cloneFrameBudget(states[start][item.Index], budget, "block working frame")
		if cloneErr != nil {
			setMethodAnalysisError(&result, cloneErr)
			break
		}
		normalFlow := true
		for index, instruction := range block.Instructions {
			if index%256 == 0 && ctx.Err() != nil {
				markMethodCancelled(&result)
				break
			}
			if err := budget.charge("instruction transfer", 1+opts.Limits.MaxProvenanceSteps); err != nil {
				setMethodAnalysisError(&result, err)
				break
			}
			exceptions := classifyInstructionExceptions(cf, instruction, current)
			if exceptions.Unknown || len(exceptions.Types) != 0 {
				applicable, handlerErr := handlerIndex.applicable(ctx, instruction.Offset, budget)
				if handlerErr != nil {
					if handlerErr == context.Canceled {
						markMethodCancelled(&result)
					} else {
						setMethodAnalysisError(&result, handlerErr)
					}
					break
				}
				selected := applicable
				if !exceptions.Unknown {
					if err := budget.charge("typed handler selection", len(applicable)); err != nil {
						setMethodAnalysisError(&result, err)
						break
					}
					matched := make([]bool, len(applicable))
					for _, thrown := range exceptions.Types {
						for handlerIndex, handler := range applicable {
							if ctx.Err() != nil {
								markMethodCancelled(&result)
								break
							}
							if err := budget.charge("typed handler dispatch", 1); err != nil {
								setMethodAnalysisError(&result, err)
								break
							}
							catchType := handler.CatchType
							if catchType == "" {
								catchType = "java/lang/Throwable"
							}
							if exceptionAssignableTo(thrown, catchType) {
								matched[handlerIndex] = true
								break
							}
						}
						if result.Unsupported != "" || result.BudgetExhausted != "" || result.Cancelled {
							break
						}
					}
					selected = make([]exceptionHandler, 0, len(applicable))
					for handlerIndex, handler := range applicable {
						if matched[handlerIndex] {
							selected = append(selected, handler)
						}
					}
				}
				for _, handler := range selected {
					catchType := handler.CatchType
					if catchType == "" {
						catchType = "java/lang/Throwable"
					}
					if ctx.Err() != nil {
						markMethodCancelled(&result)
						break
					}
					exceptional, exceptionalErr := cloneFrameBudget(current, budget, "exception instruction frame")
					if exceptionalErr != nil {
						setMethodAnalysisError(&result, exceptionalErr)
						break
					}
					exceptional.Stack = []abstractValue{{
						Kinds: kindUnknown, Verifier: verifierReference,
						Reference: catchType, Nullness: nullnessNonNull, Width: 1,
					}}
					if invokesUninitializedThis(cf, instruction, current) {
						poisonUninitializedThisAliases(&exceptional)
					}
					if exceptions.Unproven || exceptions.Unknown {
						exceptional.Unproven = true
					}
					if !mergeInto(handler.Handler, exceptional) {
						break
					}
				}
				if result.Unsupported != "" || result.BudgetExhausted != "" || result.Cancelled {
					break
				}
			}
			if exceptions.DefinitelyAbrupt {
				normalFlow = false
				break
			}
			if err := transferInstruction(cf, method, instruction, &current, &result, opts, budget); err != nil {
				if _, ok := err.(*noNormalFlowError); ok {
					normalFlow = false
					break
				}
				if _, ok := err.(*abstractBudgetError); ok {
					setMethodAnalysisError(&result, err)
				} else if _, ok := err.(*unsupportedBytecodeError); ok {
					result.Unsupported = fmt.Sprintf("bytecode offset %d opcode 0x%02x: %v", instruction.Offset, instruction.Opcode, err)
				} else {
					result.Unsupported = fmt.Sprintf("bytecode offset %d opcode 0x%02x: %v", instruction.Offset, instruction.Opcode, err)
					result.VerifierInvalid = true
				}
				break
			}
		}
		if result.Unsupported != "" || result.BudgetExhausted != "" || result.Cancelled {
			break
		}
		if !normalFlow {
			continue
		}
		for _, successor := range block.Successors {
			if ctx.Err() != nil {
				markMethodCancelled(&result)
				break
			}
			if isNormalSuccessor(block, successor) && !mergeInto(successor, current) {
				break
			}
			if result.Unsupported != "" || result.BudgetExhausted != "" {
				break
			}
		}
	}
	return result
}

func validateStackMapStructure(
	cf *classModel,
	method *methodModel,
	cfg *controlFlowGraph,
	budget *abstractBudget,
) (map[uint32]stackMapFrame, error) {
	if cf == nil || method == nil || method.Code == nil || cfg == nil || cf.Major < 50 {
		return map[uint32]stackMapFrame{}, nil
	}
	if err := budget.charge("StackMap preflight maps", 2); err != nil {
		return nil, err
	}
	frames := make(map[uint32]stackMapFrame)
	required := make(map[uint32]struct{})
	newOffsets := make(map[uint32]struct{})
	for _, blockOffset := range cfg.Order {
		if err := budget.charge("StackMap CFG scan", 1); err != nil {
			return nil, err
		}
		block := cfg.Blocks[blockOffset]
		if block == nil {
			return nil, fmt.Errorf("StackMapTable validation found missing block %d", blockOffset)
		}
		for _, ins := range block.Instructions {
			if err := budget.charge("StackMap instruction scan", 1+len(ins.Targets)); err != nil {
				return nil, err
			}
			if ins.Opcode == 0xbb {
				if _, exists := newOffsets[ins.Offset]; !exists {
					if err := budget.charge("StackMap new offset retention", 1); err != nil {
						return nil, err
					}
				}
				newOffsets[ins.Offset] = struct{}{}
			}
			for _, target := range ins.Targets {
				if target != cfg.Entry {
					if _, exists := required[target]; !exists {
						if err := budget.charge("StackMap required target retention", 1); err != nil {
							return nil, err
						}
					}
					required[target] = struct{}{}
				}
			}
		}
	}
	for _, handler := range method.Code.Handlers {
		if err := budget.charge("StackMap handler scan", 1); err != nil {
			return nil, err
		}
		if handler.Handler != cfg.Entry {
			if _, exists := required[handler.Handler]; !exists {
				if err := budget.charge("StackMap handler target retention", 1); err != nil {
					return nil, err
				}
			}
			required[handler.Handler] = struct{}{}
		}
	}
	for _, declared := range method.Code.StackMapFrames {
		verificationCount := len(declared.Locals) + len(declared.Stack)
		if err := budget.charge("StackMap frame scan", 1+verificationCount); err != nil {
			return nil, err
		}
		if _, duplicate := frames[declared.Offset]; duplicate {
			return nil, fmt.Errorf("duplicate StackMapTable frame at bytecode offset %d", declared.Offset)
		}
		if cfg.Blocks[declared.Offset] == nil {
			return nil, fmt.Errorf("StackMapTable frame offset %d is not a basic-block boundary", declared.Offset)
		}
		for _, values := range [][]stackMapVerification{declared.Locals, declared.Stack} {
			for _, value := range values {
				if value.Tag == 8 {
					if _, ok := newOffsets[uint32(value.Offset)]; !ok {
						return nil, fmt.Errorf("uninitialized StackMapTable offset %d does not name new", value.Offset)
					}
				}
			}
		}
		if err := budget.charge("StackMap frame retention", 1); err != nil {
			return nil, err
		}
		frames[declared.Offset] = declared
	}
	if err := budget.charge("StackMap required target order", len(required)); err != nil {
		return nil, err
	}
	for width := 1; width < len(required); width *= 2 {
		if err := budget.charge("StackMap required target sort", len(required)); err != nil {
			return nil, err
		}
		if width > len(required)/2 {
			break
		}
	}
	for _, target := range sortedOffsets(required) {
		if _, ok := frames[target]; !ok {
			return nil, fmt.Errorf("major-%d method requires StackMapTable frame at bytecode offset %d", cf.Major, target)
		}
	}
	return frames, nil
}

func validateFrameAgainstStackMap(cf *classModel, incoming frame, declared stackMapFrame, budget *abstractBudget) error {
	if err := budget.charge(
		"incoming StackMap frame validation",
		1+len(incoming.Locals)+len(incoming.Stack)+len(declared.Locals)+len(declared.Stack),
	); err != nil {
		return err
	}
	localIndex := 0
	for index, expected := range declared.Locals {
		if index%256 == 0 {
			if err := budget.charge("incoming StackMap local poll", 0); err != nil {
				return err
			}
		}
		if localIndex >= len(incoming.Locals) {
			return fmt.Errorf("local %d exceeds max_locals", index)
		}
		if err := validateValueAgainstStackMap(cf, incoming.Locals[localIndex], expected); err != nil {
			return fmt.Errorf("local %d: %w", index, err)
		}
		localIndex++
		if expected.Tag == 3 || expected.Tag == 4 {
			if localIndex >= len(incoming.Locals) || incoming.Locals[localIndex].Width != 0 {
				return fmt.Errorf("local %d lacks category-two top slot", index)
			}
			localIndex++
		}
	}
	for ; localIndex < len(incoming.Locals); localIndex++ {
		if incoming.Locals[localIndex].Width != 0 {
			return fmt.Errorf("undeclared live local slot %d", localIndex)
		}
	}
	if len(incoming.Stack) != len(declared.Stack) {
		return fmt.Errorf("stack height %d does not match declared height %d", len(incoming.Stack), len(declared.Stack))
	}
	for index, expected := range declared.Stack {
		if index%256 == 0 {
			if err := budget.charge("incoming StackMap stack poll", 0); err != nil {
				return err
			}
		}
		if err := validateValueAgainstStackMap(cf, incoming.Stack[index], expected); err != nil {
			return fmt.Errorf("stack %d: %w", index, err)
		}
	}
	return nil
}

func validateValueAgainstStackMap(cf *classModel, actual abstractValue, expected stackMapVerification) error {
	want := verifierTop
	switch expected.Tag {
	case 0:
		if actual.Width == 0 {
			return nil
		}
		return fmt.Errorf("expected top, got verifier type %d", actual.Verifier)
	case 1:
		want = verifierInt
	case 2:
		want = verifierFloat
	case 3:
		want = verifierDouble
	case 4:
		want = verifierLong
	case 5:
		if isKnownNull(actual) {
			return nil
		}
		return fmt.Errorf("expected null, got verifier type %d", actual.Verifier)
	case 6:
		if actual.Verifier == verifierUninitialized && actual.ObjectID == receiverObjectID {
			return nil
		}
		return fmt.Errorf("expected uninitializedThis")
	case 7:
		if isReferenceValue(actual) && (isKnownNull(actual) || referenceAssignableTo(cf, actual.Reference, expected.ClassName)) {
			return nil
		}
		return fmt.Errorf("reference %q is not assignable to %s", actual.Reference, expected.ClassName)
	case 8:
		if actual.Verifier == verifierUninitialized && actual.ObjectID == allocationObjectID(uint32(expected.Offset)) {
			return nil
		}
		return fmt.Errorf("expected uninitialized allocation at %d", expected.Offset)
	default:
		return fmt.Errorf("invalid verification type tag %d", expected.Tag)
	}
	if actual.Verifier != want || actual.Width != verifierWidth(want) {
		return fmt.Errorf("expected verifier type %d, got %d", want, actual.Verifier)
	}
	return nil
}

func setMethodAnalysisError(result *methodAnalysis, err error) {
	if errors.Is(err, context.Canceled) {
		markMethodCancelled(result)
		return
	}
	if budgetErr, ok := err.(*abstractBudgetError); ok {
		result.BudgetExhausted = budgetErr.Error()
		return
	}
	result.Unsupported = err.Error()
}

func markMethodCancelled(result *methodAnalysis) {
	result.Cancelled = true
	clearMethodExecution(result)
}

func clearMethodExecution(result *methodAnalysis) {
	result.RequestExec = false
	result.Evidence = nil
	result.Source = provenanceStep{}
	result.Sink = provenanceStep{}
	result.SinkResults = nil
	result.Summary = emptyMethodSummary()
}

func initialFrame(
	cf *classModel,
	method *methodModel,
	descriptor methodDescriptor,
	opts Options,
	budget *abstractBudget,
	summarizing bool,
) (frame, error) {
	if err := budget.charge("initial frame", 1+int(method.Code.MaxLocals)+len(descriptor.Parameters)); err != nil {
		return frame{}, err
	}
	result := frame{
		Locals: make([]abstractValue, int(method.Code.MaxLocals)), Fields: make(map[fieldKey]abstractValue),
		Heap:       make(map[uint32]heapObject),
		ThisUninit: method.Name == "<init>",
	}
	index := 0
	if method.Access&0x0008 == 0 {
		if index >= len(result.Locals) {
			return frame{}, fmt.Errorf("receiver exceeds max_locals %d", method.Code.MaxLocals)
		}
		verifier := verifierReference
		if method.Name == "<init>" {
			verifier = verifierUninitialized
		}
		result.Locals[index] = abstractValue{
			Kinds: kindUnknown, ObjectID: receiverObjectID, Verifier: verifier,
			Reference: cf.Name, RuntimeType: cf.Name, Nullness: nullnessNonNull, Width: 1,
		}
		if summarizing {
			result.Locals[index].Arguments.add(index)
		}
		index++
	}
	serverEntry := isServletEntry(cf, method)
	for _, parameter := range descriptor.Parameters {
		if index+int(parameter.Width) > len(result.Locals) {
			return frame{}, fmt.Errorf("parameters exceed max_locals %d", method.Code.MaxLocals)
		}
		value := valueForDescriptor(parameter)
		if parameter.Width == 1 && (parameter.Object != "" || parameter.Array) {
			value.ObjectID = parameterObjectID(index)
		}
		if summarizing {
			value.Arguments.add(index)
		}
		if serverEntry && !summarizing {
			if _, ok := requestParameterTypes[parameter.Object]; ok && !parameter.Array {
				value.Taint = taintRequestParameter | taintRequestHeader | taintRequestBody | taintCookie
				value.Provenance = []provenanceStep{{API: "servlet-entry:" + method.Name}}
			}
		}
		result.Locals[index] = value
		if parameter.Width == 2 {
			result.Locals[index+1] = abstractValue{}
		}
		index += int(parameter.Width)
	}
	return result, nil
}

func isServletEntry(cf *classModel, method *methodModel) bool {
	if method.Access&(0x0008|0x0002) != 0 {
		return false
	}
	javaxHTTP := "(Ljavax/servlet/http/HttpServletRequest;Ljavax/servlet/http/HttpServletResponse;)V"
	jakartaHTTP := "(Ljakarta/servlet/http/HttpServletRequest;Ljakarta/servlet/http/HttpServletResponse;)V"
	if cf.Super == "org/apache/jasper/runtime/HttpJspBase" && method.Name == "_jspService" {
		return method.Descriptor == javaxHTTP || method.Descriptor == jakartaHTTP
	}
	if cf.Super == "javax/servlet/GenericServlet" {
		return method.Name == "service" && method.Descriptor ==
			"(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"
	}
	if cf.Super == "jakarta/servlet/GenericServlet" {
		return method.Name == "service" && method.Descriptor ==
			"(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V"
	}
	if cf.Super == "javax/servlet/http/HttpServlet" || cf.Super == "jakarta/servlet/http/HttpServlet" {
		if !isHTTPServletEntryMethod(method.Name) {
			return false
		}
		if cf.Super == "javax/servlet/http/HttpServlet" {
			return method.Descriptor == javaxHTTP || method.Name == "service" && method.Descriptor ==
				"(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"
		}
		return method.Descriptor == jakartaHTTP || method.Name == "service" && method.Descriptor ==
			"(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V"
	}
	if directHierarchy(cf, "javax/servlet/Servlet") {
		return method.Name == "service" && method.Descriptor ==
			"(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V"
	}
	if directHierarchy(cf, "jakarta/servlet/Servlet") {
		return method.Name == "service" && method.Descriptor ==
			"(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;)V"
	}
	if directHierarchy(cf, "javax/servlet/Filter") {
		return method.Name == "doFilter" && method.Descriptor ==
			"(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;Ljavax/servlet/FilterChain;)V"
	}
	if directHierarchy(cf, "jakarta/servlet/Filter") {
		return method.Name == "doFilter" && method.Descriptor ==
			"(Ljakarta/servlet/ServletRequest;Ljakarta/servlet/ServletResponse;Ljakarta/servlet/FilterChain;)V"
	}
	return false
}

func isHTTPServletEntryMethod(name string) bool {
	switch name {
	case "service", "doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions", "doTrace":
		return true
	default:
		return false
	}
}

func directHierarchy(cf *classModel, name string) bool {
	if cf.Super == name {
		return true
	}
	for _, candidate := range cf.Interfaces {
		if candidate == name {
			return true
		}
	}
	return false
}

func transferInstruction(
	cf *classModel,
	method *methodModel,
	ins instruction,
	f *frame,
	analysis *methodAnalysis,
	opts Options,
	budget *abstractBudget,
) error {
	push := func(value abstractValue) error {
		if err := budget.chargeValueCopies("operand stack value retention", 0, []abstractValue{value}, 1); err != nil {
			return err
		}
		return pushValue(f, value, method.Code, opts.Limits)
	}
	pop := func(width uint8) (abstractValue, error) { return popValue(f, width) }
	switch op := ins.Opcode; {
	case op == 0x00:
		return nil
	case op == 0x01:
		return push(abstractValue{Kinds: kindUnknown, Verifier: verifierNull, Nullness: nullnessNull, Width: 1})
	case op >= 0x02 && op <= 0x08:
		return push(constantValueAbstract(strconv.Itoa(int(op)-3), verifierInt, 1, opts.Limits))
	case op == 0x09 || op == 0x0a:
		return push(constantValueAbstract(strconv.Itoa(int(op)-0x09), verifierLong, 2, opts.Limits))
	case op >= 0x0b && op <= 0x0d:
		return push(constantValueAbstract(strconv.Itoa(int(op)-0x0b), verifierFloat, 1, opts.Limits))
	case op == 0x0e || op == 0x0f:
		return push(constantValueAbstract(strconv.Itoa(int(op)-0x0e), verifierDouble, 2, opts.Limits))
	case op == 0x10:
		return push(constantValueAbstract(strconv.Itoa(int(int8(ins.Operands[0]))), verifierInt, 1, opts.Limits))
	case op == 0x11:
		return push(constantValueAbstract(strconv.Itoa(int(int16(binary.BigEndian.Uint16(ins.Operands)))), verifierInt, 1, opts.Limits))
	case op >= 0x12 && op <= 0x14:
		return transferLDC(cf, ins, f, method.Code, opts.Limits, budget)
	case op >= 0x15 && op <= 0x19:
		return loadLocal(f, int(ins.Operands[0]), loadStoreWidth(op), loadStoreVerifier(op), push)
	case op >= 0x1a && op <= 0x2d:
		index, width := implicitLoad(op)
		return loadLocal(f, index, width, loadStoreVerifier(op), push)
	case op >= 0x2e && op <= 0x35:
		return transferArrayLoad(op, f, push, opts.Limits, budget)
	case op >= 0x36 && op <= 0x3a:
		value, err := pop(loadStoreWidth(op))
		if err != nil {
			return err
		}
		if !valueMatchesLoadStore(op, value) {
			return fmt.Errorf("store opcode requires compatible verifier type")
		}
		return storeLocal(f, int(ins.Operands[0]), value, budget)
	case op >= 0x3b && op <= 0x4e:
		index, width := implicitStore(op)
		value, err := pop(width)
		if err != nil {
			return err
		}
		if !valueMatchesLoadStore(op, value) {
			return fmt.Errorf("store opcode requires compatible verifier type")
		}
		return storeLocal(f, index, value, budget)
	case op >= 0x4f && op <= 0x56:
		return transferArrayStore(cf, op, f, opts.Limits, budget)
	case op >= 0x57 && op <= 0x5f:
		return transferStackOperation(op, f, method.Code, opts.Limits, budget)
	case op >= 0x60 && op <= 0x83:
		return transferArithmetic(op, f, push, opts.Limits, budget)
	case op == 0x84:
		return validateIINC(f, int(ins.Operands[0]))
	case op >= 0x85 && op <= 0x93:
		return transferConversion(op, f, push)
	case op >= 0x94 && op <= 0x98:
		return transferComparison(op, f, push)
	case op >= 0x99 && op <= 0x9e:
		value, err := pop(1)
		if err != nil {
			return err
		}
		if value.Verifier != verifierInt {
			return fmt.Errorf("integer branch requires int verifier type")
		}
		return nil
	case op >= 0x9f && op <= 0xa4:
		right, err := pop(1)
		if err != nil {
			return err
		}
		left, err := pop(1)
		if err != nil {
			return err
		}
		if left.Verifier != verifierInt || right.Verifier != verifierInt {
			return fmt.Errorf("integer comparison branch requires int verifier types")
		}
		return nil
	case op == 0xa5 || op == 0xa6:
		right, err := pop(1)
		if err != nil {
			return err
		}
		left, err := pop(1)
		if err != nil {
			return err
		}
		if !isReferenceValue(left) || !isReferenceValue(right) {
			return fmt.Errorf("reference comparison branch requires reference verifier types")
		}
		return nil
	case op == 0xa7 || op == 0xc8:
		return nil
	case op == 0xa8 || op == 0xa9 || op == 0xc9:
		return &unsupportedBytecodeError{detail: "reachable jsr/ret is unsupported"}
	case op == 0xaa || op == 0xab:
		value, err := pop(1)
		if err != nil {
			return err
		}
		if value.Verifier != verifierInt {
			return fmt.Errorf("switch key requires int verifier type")
		}
		return nil
	case op >= 0xac && op <= 0xb1:
		return transferReturn(op, cf, method, f, analysis)
	case op >= 0xb2 && op <= 0xb5:
		return transferField(cf, method, ins, f, push, opts.Limits, budget)
	case op >= 0xb6 && op <= 0xba:
		return transferInvoke(cf, ins, f, analysis, method.Code, opts, budget)
	case op == 0xbb:
		name, err := classOperandName(cf, ins)
		if err != nil {
			return err
		}
		return push(abstractValue{
			Kinds: kindUnknown, ObjectID: allocationObjectID(ins.Offset), Verifier: verifierUninitialized,
			Reference: name, RuntimeType: name, Nullness: nullnessNonNull, Width: 1,
		})
	case op == 0xbc || op == 0xbd:
		reference := ""
		if op == 0xbd {
			name, err := classOperandName(cf, ins)
			if err != nil {
				return err
			}
			if strings.HasPrefix(name, "[") {
				reference = "[" + name
			} else {
				reference = "[L" + name + ";"
			}
		} else {
			reference = primitiveArrayDescriptor(ins.Operands[0])
			if reference == "" {
				return fmt.Errorf("newarray has invalid atype %d", ins.Operands[0])
			}
		}
		count, err := pop(1)
		if err != nil {
			return err
		}
		if count.Verifier != verifierInt {
			return fmt.Errorf("array size requires int verifier type")
		}
		value := abstractValue{
			Kinds: kindUnknown, ObjectID: allocationObjectID(ins.Offset), Verifier: verifierReference,
			Reference: reference, RuntimeType: reference, Nullness: nullnessNonNull, Width: 1,
		}
		if length, known := exactIntegerConstant(count); known {
			if length < 0 {
				return &noNormalFlowError{}
			}
			value.ArrayLength, value.LengthKnown = length, true
		}
		return push(value)
	case op == 0xbe:
		array, err := pop(1)
		if err != nil {
			return err
		}
		if err := requireDereference(cf, array, "", "arraylength"); err != nil {
			return err
		}
		if !strings.HasPrefix(array.Reference, "[") {
			return fmt.Errorf("arraylength requires array reference type")
		}
		return push(abstractValue{Kinds: kindUnknown, Verifier: verifierInt, Width: 1})
	case op == 0xbf:
		value, err := pop(1)
		if err != nil {
			return err
		}
		if !isReferenceValue(value) {
			return fmt.Errorf("athrow requires reference verifier type")
		}
		throwable, descriptorErr := parseFieldDescriptor("Ljava/lang/Throwable;")
		if descriptorErr != nil {
			return descriptorErr
		}
		if !isKnownNull(value) && !valueAssignmentCompatible(cf, value, throwable) {
			return fmt.Errorf("athrow value %q is not Throwable-compatible", value.Reference)
		}
		return nil
	case op == 0xc0:
		name, err := classOperandName(cf, ins)
		if err != nil {
			return err
		}
		value, err := pop(1)
		if err != nil {
			return err
		}
		if !isReferenceValue(value) {
			return fmt.Errorf("checkcast requires reference verifier type")
		}
		if isKnownNull(value) {
			return push(value)
		}
		if runtimeType := exactRuntimeType(value); runtimeType != "" && !referenceAssignableTo(cf, runtimeType, name) {
			return &noNormalFlowError{}
		}
		value.Reference = name
		return push(value)
	case op == 0xc1:
		if err := validateClassOperand(cf, ins); err != nil {
			return err
		}
		value, err := pop(1)
		if err != nil {
			return err
		}
		if !isReferenceValue(value) {
			return fmt.Errorf("instanceof requires reference verifier type")
		}
		return push(abstractValue{Kinds: kindUnknown, Verifier: verifierInt, Width: 1})
	case op == 0xc2 || op == 0xc3:
		value, err := pop(1)
		if err != nil {
			return err
		}
		return requireDereference(cf, value, "", "monitor")
	case op == 0xc4:
		return transferWide(ins, f, push, budget)
	case op == 0xc5:
		if err := validateClassOperand(cf, ins); err != nil {
			return err
		}
		dimensions := int(ins.Operands[2])
		name, err := cf.className(binary.BigEndian.Uint16(ins.Operands[:2]))
		if err != nil {
			return err
		}
		arrayType, err := parseFieldDescriptor(name)
		if err != nil || !arrayType.Array || dimensions > strings.Count(name, "[") {
			return fmt.Errorf("multianewarray dimensions %d are incompatible with %q", dimensions, name)
		}
		for i := 0; i < dimensions; i++ {
			value, popErr := pop(1)
			if popErr != nil {
				return popErr
			}
			if value.Verifier != verifierInt {
				return fmt.Errorf("multianewarray dimension requires int verifier type")
			}
			if dimension, known := exactIntegerConstant(value); known && dimension < 0 {
				return &noNormalFlowError{}
			}
		}
		return push(abstractValue{
			Kinds: kindUnknown, ObjectID: allocationObjectID(ins.Offset), Verifier: verifierReference,
			Reference: name, RuntimeType: name, Nullness: nullnessNonNull, Width: 1,
		})
	case op == 0xc6 || op == 0xc7:
		value, err := pop(1)
		if err != nil {
			return err
		}
		if !isReferenceValue(value) {
			return fmt.Errorf("null branch requires reference verifier type")
		}
		return nil
	default:
		return &unsupportedBytecodeError{detail: "unsupported transfer"}
	}
}

func instructionMayThrow(cf *classModel, ins instruction) bool {
	op := ins.Opcode
	switch {
	case op >= 0x2e && op <= 0x35, op >= 0x4f && op <= 0x56:
		return true
	case op == 0x6c || op == 0x6d || op == 0x70 || op == 0x71:
		return true
	case op >= 0xb2 && op <= 0xc0:
		switch op {
		case 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba,
			0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0:
			return true
		}
	case op >= 0xc0 && op <= 0xc3 || op == 0xc5:
		return true
	case op >= 0x12 && op <= 0x14:
		if cf == nil {
			return false
		}
		index := uint16(ins.Operands[0])
		if op != 0x12 {
			if len(ins.Operands) < 2 {
				return false
			}
			index = binary.BigEndian.Uint16(ins.Operands[:2])
		}
		entry, err := cf.poolEntry(index)
		if err != nil {
			return false
		}
		return entry.tag == cpString || entry.tag == cpClass || entry.tag == cpMethodType ||
			entry.tag == cpMethodHandle || entry.tag == cpDynamic
	}
	return false
}

var platformExceptionSuper = map[string]string{
	"java/lang/Throwable":                      "",
	"java/lang/Error":                          "java/lang/Throwable",
	"java/lang/LinkageError":                   "java/lang/Error",
	"java/lang/BootstrapMethodError":           "java/lang/LinkageError",
	"java/lang/VirtualMachineError":            "java/lang/Error",
	"java/lang/OutOfMemoryError":               "java/lang/VirtualMachineError",
	"java/lang/Exception":                      "java/lang/Throwable",
	"java/lang/RuntimeException":               "java/lang/Exception",
	"java/lang/ArithmeticException":            "java/lang/RuntimeException",
	"java/lang/ClassCastException":             "java/lang/RuntimeException",
	"java/lang/NullPointerException":           "java/lang/RuntimeException",
	"java/lang/NegativeArraySizeException":     "java/lang/RuntimeException",
	"java/lang/IndexOutOfBoundsException":      "java/lang/RuntimeException",
	"java/lang/ArrayIndexOutOfBoundsException": "java/lang/IndexOutOfBoundsException",
	"java/lang/ArrayStoreException":            "java/lang/RuntimeException",
	"java/lang/IllegalMonitorStateException":   "java/lang/RuntimeException",
}

func validateHandlerCatchTypes(handlers []exceptionHandler, budget *abstractBudget) error {
	if err := budget.charge("handler catch type validation", len(handlers)); err != nil {
		return err
	}
	for index, handler := range handlers {
		if index%256 == 0 {
			if err := budget.charge("handler catch type poll", 0); err != nil {
				return err
			}
		}
		if handler.CatchType == "" {
			continue
		}
		if _, known := platformExceptionSuper[handler.CatchType]; !known {
			return fmt.Errorf("handler catch type %q is not a proven Throwable subtype", handler.CatchType)
		}
	}
	return nil
}

func classifyInstructionExceptions(cf *classModel, ins instruction, state frame) instructionExceptions {
	if !instructionMayThrow(cf, ins) {
		return instructionExceptions{}
	}
	op := ins.Opcode
	switch {
	case op == 0x6c || op == 0x6d || op == 0x70 || op == 0x71:
		if len(state.Stack) == 0 {
			return instructionExceptions{Unknown: true}
		}
		divisor := state.Stack[len(state.Stack)-1]
		if divisor.Verifier != arithmeticVerifier(op) {
			return instructionExceptions{Unknown: true}
		}
		if value, ok := exactIntegerConstant(divisor); ok {
			if value == 0 {
				return instructionExceptions{Types: []string{"java/lang/ArithmeticException"}, DefinitelyAbrupt: true}
			}
			return instructionExceptions{}
		}
		return instructionExceptions{Types: []string{"java/lang/ArithmeticException"}}
	case op >= 0x12 && op <= 0x14:
		index, ok := ldcConstantIndex(ins)
		if !ok || cf == nil || int(index) >= len(cf.Pool) {
			return instructionExceptions{Unknown: true}
		}
		if cf.Pool[index].tag == cpDynamic {
			failed := int(index) < len(cf.BootstrapFailures) && cf.BootstrapFailures[index]
			return instructionExceptions{
				Types: []string{"java/lang/BootstrapMethodError"}, DefinitelyAbrupt: failed, Unproven: !failed,
			}
		}
		return instructionExceptions{Unknown: true}
	case op == 0xbc || op == 0xbd:
		count, ok := stackValueFromTop(state, 0)
		if !ok || count.Verifier != verifierInt {
			return instructionExceptions{Unknown: true}
		}
		if value, constant := exactIntegerConstant(count); constant && value < 0 {
			return instructionExceptions{Types: []string{"java/lang/NegativeArraySizeException"}, DefinitelyAbrupt: true}
		}
		return instructionExceptions{Types: []string{"java/lang/OutOfMemoryError"}}
	case op == 0xc5:
		if len(ins.Operands) != 3 {
			return instructionExceptions{Unknown: true}
		}
		dimensions := int(ins.Operands[2])
		if dimensions <= 0 {
			return instructionExceptions{Unknown: true}
		}
		allExactNonNegative := true
		for depth := 0; depth < dimensions; depth++ {
			value, ok := stackValueFromTop(state, depth)
			if !ok || value.Verifier != verifierInt {
				return instructionExceptions{Unknown: true}
			}
			if dimension, known := exactIntegerConstant(value); known {
				if dimension < 0 {
					return instructionExceptions{
						Types: []string{"java/lang/NegativeArraySizeException"}, DefinitelyAbrupt: true,
					}
				}
				continue
			}
			allExactNonNegative = false
		}
		if allExactNonNegative {
			return instructionExceptions{Types: []string{"java/lang/OutOfMemoryError"}}
		}
		return instructionExceptions{Types: []string{"java/lang/NegativeArraySizeException", "java/lang/OutOfMemoryError"}}
	case op == 0xba:
		if len(ins.Operands) != 4 || cf == nil {
			return instructionExceptions{Unknown: true}
		}
		index := binary.BigEndian.Uint16(ins.Operands[:2])
		failed := int(index) < len(cf.BootstrapFailures) && cf.BootstrapFailures[index]
		return instructionExceptions{
			Types: []string{"java/lang/BootstrapMethodError"}, DefinitelyAbrupt: failed, Unproven: !failed,
		}
	case op >= 0xb6 && op <= 0xb9:
		if op == 0xb8 {
			return instructionExceptions{Unknown: true}
		}
		ref, err := resolveInvokeOperand(cf, ins)
		if err != nil {
			return instructionExceptions{Unknown: true}
		}
		descriptor, err := parseMethodDescriptor(ref.Descriptor)
		if err != nil {
			return instructionExceptions{Unknown: true}
		}
		receiver, ok := stackValueFromTop(state, len(descriptor.Parameters))
		if ok && isKnownNull(receiver) {
			return instructionExceptions{
				Types: []string{"java/lang/LinkageError", "java/lang/NullPointerException"}, DefinitelyAbrupt: true,
			}
		}
		return instructionExceptions{Unknown: true}
	case op == 0xb2 || op == 0xb3:
		ref, err := resolveFieldOperand(cf, ins)
		return instructionExceptions{Unknown: true, Unproven: err != nil || cf == nil || ref.Owner != cf.Name}
	case op >= 0x2e && op <= 0x35:
		array, index, ok := arrayOperands(state, false)
		if !ok || !isReferenceValue(array) || !isKnownNull(array) && validateArrayOpcode(op, array.Reference) != nil {
			return instructionExceptions{Unknown: true}
		}
		return classifyArrayAccess(array, index)
	case op >= 0x4f && op <= 0x56:
		array, index, ok := arrayOperands(state, true)
		value, valueOK := stackValueFromTop(state, 0)
		want, _ := arrayStoreType(op)
		validValue := valueOK && (want == verifierReference && isReferenceValue(value) || want != verifierReference && value.Verifier == want)
		if !ok || !validValue || !isReferenceValue(array) || !isKnownNull(array) && validateArrayOpcode(op, array.Reference) != nil {
			return instructionExceptions{Unknown: true}
		}
		result := classifyArrayAccess(array, index)
		if op == 0x53 && !result.DefinitelyAbrupt {
			if referenceArrayStoreDefinitelyFails(cf, array, value) {
				return instructionExceptions{Types: []string{"java/lang/ArrayStoreException"}, DefinitelyAbrupt: true}
			}
			result.Types = append(result.Types, "java/lang/ArrayStoreException")
		}
		return result
	case op == 0xbe:
		array, ok := stackValueFromTop(state, 0)
		if ok && isKnownNull(array) {
			return instructionExceptions{Types: []string{"java/lang/NullPointerException"}, DefinitelyAbrupt: true}
		}
		return instructionExceptions{Types: []string{"java/lang/NullPointerException"}}
	case op == 0xb4:
		ref, refErr := resolveFieldOperand(cf, ins)
		unproven := refErr != nil || cf == nil || ref.Owner != cf.Name
		receiver, ok := stackValueFromTop(state, 0)
		if ok && isKnownNull(receiver) {
			return instructionExceptions{Types: []string{"java/lang/NullPointerException"}, Unproven: unproven}
		}
		return instructionExceptions{Unknown: true, Unproven: unproven}
	case op == 0xb5:
		ref, refErr := resolveFieldOperand(cf, ins)
		fieldType, typeErr := parseFieldDescriptor(ref.Descriptor)
		value, valueOK := stackValueFromTop(state, 0)
		if refErr != nil || typeErr != nil || !valueOK || !valueAssignmentCompatible(cf, value, fieldType) {
			return instructionExceptions{Unknown: true}
		}
		receiver, ok := stackValueFromTop(state, 1)
		if ok && isKnownNull(receiver) {
			return instructionExceptions{
				Types:    []string{"java/lang/NullPointerException"},
				Unproven: refErr != nil || cf == nil || ref.Owner != cf.Name,
			}
		}
		return instructionExceptions{Unknown: true, Unproven: refErr != nil || cf == nil || ref.Owner != cf.Name}
	case op == 0xc0:
		value, ok := stackValueFromTop(state, 0)
		if !ok || !isReferenceValue(value) {
			return instructionExceptions{Unknown: true}
		}
		if isKnownNull(value) {
			return instructionExceptions{}
		}
		target, err := classOperandName(cf, ins)
		if err == nil {
			if runtimeType := exactRuntimeType(value); runtimeType != "" && !referenceAssignableTo(cf, runtimeType, target) {
				return instructionExceptions{Types: []string{"java/lang/ClassCastException"}, DefinitelyAbrupt: true}
			}
		}
		return instructionExceptions{Types: []string{"java/lang/ClassCastException"}}
	case op == 0xc2 || op == 0xc3:
		value, ok := stackValueFromTop(state, 0)
		if ok && isKnownNull(value) {
			return instructionExceptions{Types: []string{"java/lang/NullPointerException"}, DefinitelyAbrupt: true}
		}
		if op == 0xc3 {
			return instructionExceptions{Types: []string{"java/lang/IllegalMonitorStateException"}}
		}
		return instructionExceptions{}
	case op == 0xbf:
		value, ok := stackValueFromTop(state, 0)
		if ok && isKnownNull(value) {
			return instructionExceptions{Types: []string{"java/lang/NullPointerException"}, DefinitelyAbrupt: true}
		}
		throwable, descriptorErr := parseFieldDescriptor("Ljava/lang/Throwable;")
		if !ok || descriptorErr != nil || !valueAssignmentCompatible(cf, value, throwable) {
			return instructionExceptions{Unknown: true}
		}
		return instructionExceptions{Unknown: true, DefinitelyAbrupt: true}
	default:
		return instructionExceptions{Unknown: true}
	}
}

func stackValueFromTop(state frame, index int) (abstractValue, bool) {
	position := len(state.Stack) - index - 1
	if position < 0 || position >= len(state.Stack) {
		return abstractValue{}, false
	}
	return state.Stack[position], true
}

func arrayOperands(state frame, store bool) (abstractValue, abstractValue, bool) {
	indexDepth := 0
	arrayDepth := 1
	if store {
		indexDepth = 1
		arrayDepth = 2
	}
	index, indexOK := stackValueFromTop(state, indexDepth)
	array, arrayOK := stackValueFromTop(state, arrayDepth)
	return array, index, indexOK && arrayOK && index.Verifier == verifierInt
}

func classifyArrayAccess(array, index abstractValue) instructionExceptions {
	if isKnownNull(array) {
		return instructionExceptions{Types: []string{"java/lang/NullPointerException"}, DefinitelyAbrupt: true}
	}
	result := instructionExceptions{Types: []string{"java/lang/NullPointerException", "java/lang/ArrayIndexOutOfBoundsException"}}
	if array.Nullness == nullnessNonNull {
		result.Types = result.Types[1:]
	}
	if array.LengthKnown {
		if value, ok := exactIntegerConstant(index); ok {
			if value < 0 || value >= array.ArrayLength {
				return instructionExceptions{Types: []string{"java/lang/ArrayIndexOutOfBoundsException"}, DefinitelyAbrupt: true}
			}
			if array.Nullness == nullnessNonNull {
				return instructionExceptions{}
			}
		}
	}
	return result
}

func exactIntegerConstant(value abstractValue) (int64, bool) {
	if value.Constant == "" || value.Verifier != verifierInt && value.Verifier != verifierLong {
		return 0, false
	}
	parsed, err := strconv.ParseInt(value.Constant, 10, 64)
	return parsed, err == nil
}

func ldcConstantIndex(ins instruction) (uint16, bool) {
	if ins.Opcode == 0x12 && len(ins.Operands) == 1 {
		return uint16(ins.Operands[0]), true
	}
	if (ins.Opcode == 0x13 || ins.Opcode == 0x14) && len(ins.Operands) == 2 {
		return binary.BigEndian.Uint16(ins.Operands), true
	}
	return 0, false
}

func exceptionSetCaughtBy(types []string, catchType string) bool {
	for _, thrown := range types {
		if exceptionAssignableTo(thrown, catchType) {
			return true
		}
	}
	return false
}

func exceptionAssignableTo(thrown, catchType string) bool {
	for current := thrown; current != ""; current = platformExceptionSuper[current] {
		if current == catchType {
			return true
		}
		if _, known := platformExceptionSuper[current]; !known {
			return false
		}
	}
	return false
}

func transferLDC(cf *classModel, ins instruction, f *frame, code *codeModel, limits Limits, budget *abstractBudget) error {
	index := uint16(ins.Operands[0])
	if ins.Opcode != 0x12 {
		index = binary.BigEndian.Uint16(ins.Operands)
	}
	constant, err := cf.constantValue(index)
	if err != nil {
		return fmt.Errorf("ldc constant: %w", err)
	}
	value := abstractValue{Kinds: kindUnknown, Width: 1}
	switch constant.Kind {
	case constantString:
		value.Verifier, value.Reference, value.RuntimeType = verifierReference, "java/lang/String", "java/lang/String"
		value.Nullness, value.Kinds = nullnessNonNull, kindString
		if len(constant.String) <= limits.MaxConstantBytes {
			value.Constant = constant.String
		}
	case constantInteger:
		value.Verifier = verifierInt
	case constantFloat:
		value.Verifier = verifierFloat
	case constantLong:
		value.Verifier, value.Width = verifierLong, 2
	case constantDouble:
		value.Verifier, value.Width = verifierDouble, 2
	case constantClass:
		value.Verifier, value.Reference, value.RuntimeType = verifierReference, "java/lang/Class", "java/lang/Class"
		value.Nullness = nullnessNonNull
	case constantMethodType:
		value.Verifier, value.Reference, value.RuntimeType = verifierReference, "java/lang/invoke/MethodType", "java/lang/invoke/MethodType"
		value.Nullness = nullnessNonNull
	case constantMethodHandle:
		value.Verifier, value.Reference, value.RuntimeType = verifierReference, "java/lang/invoke/MethodHandle", "java/lang/invoke/MethodHandle"
		value.Nullness = nullnessNonNull
	case constantDynamic:
		if constant.Reference == nil {
			return fmt.Errorf("dynamic constant has no descriptor")
		}
		descriptor, descriptorErr := parseFieldDescriptor(constant.Reference.Descriptor)
		if descriptorErr != nil {
			return fmt.Errorf("dynamic constant descriptor: %w", descriptorErr)
		}
		value = valueForDescriptor(descriptor)
		if int(index) < len(cf.BootstrapFailures) && cf.BootstrapFailures[index] {
			return &noNormalFlowError{}
		}
		f.Unproven = true
	default:
		return fmt.Errorf("unsupported ldc constant kind %d", constant.Kind)
	}
	width := value.Width
	if ins.Opcode == 0x14 && width != 2 || ins.Opcode != 0x14 && width == 2 {
		return fmt.Errorf("ldc opcode is incompatible with constant kind %d", constant.Kind)
	}
	if err := budget.chargeValueCopies("ldc stack value retention", 0, []abstractValue{value}, 1); err != nil {
		return err
	}
	return pushValue(f, value, code, limits)
}

func transferArrayLoad(op byte, f *frame, push func(abstractValue) error, limits Limits, budget *abstractBudget) error {
	index, err := popValue(f, 1)
	if err != nil {
		return err
	}
	if index.Verifier != verifierInt {
		return fmt.Errorf("array index requires int verifier type")
	}
	array, err := popValue(f, 1)
	if err != nil {
		return err
	}
	if err := requireDereference(nil, array, "", "array load"); err != nil {
		return err
	}
	if array.LengthKnown {
		if offset, known := exactIntegerConstant(index); known && (offset < 0 || offset >= array.ArrayLength) {
			return &noNormalFlowError{}
		}
	}
	verifier, reference, width, err := arrayLoadType(op, array.Reference)
	if err != nil {
		return err
	}
	value := abstractValue{Kinds: kindUnknown, Verifier: verifier, Reference: reference, Width: width}
	value.Taint = array.Taint
	value.Arguments = array.Arguments
	value.SummaryOnly = array.SummaryOnly
	if err := budget.chargeValueCopies("array provenance propagation", 0, []abstractValue{{Provenance: array.Provenance}}, 1); err != nil {
		return err
	}
	value.Provenance = cloneProvenance(array.Provenance)
	exactIndex, indexKnown := exactIntegerConstant(index)
	var ordered []fieldKey
	if !indexKnown {
		ordered, err = orderedFieldKeysBudget(f.Fields, budget, "unknown-index array read")
		if err != nil {
			return err
		}
	}
	for i := 0; i < identityCount(array); i++ {
		id := identityAt(array, i)
		keys := []fieldKey{arrayElementKey(id)}
		if indexKnown {
			keys = append(keys, arrayIndexedElementKey(id, exactIndex))
		} else {
			keys = keys[:0]
			for _, key := range ordered {
				if isArrayElementKey(key, id) {
					keys = append(keys, key)
				}
			}
		}
		for _, key := range keys {
			if stored, ok := f.Fields[key]; ok && stored.Width == width {
				merged, mergeErr := mergeValues(value, stored, limits, budget)
				if mergeErr != nil {
					return mergeErr
				}
				value = merged
			}
		}
	}
	return push(value)
}

func transferArrayStore(cf *classModel, op byte, f *frame, limits Limits, budget *abstractBudget) error {
	verifier, width := arrayStoreType(op)
	value, err := popValue(f, width)
	if err != nil {
		return err
	}
	if verifier == verifierReference {
		if !isReferenceValue(value) {
			return fmt.Errorf("reference array store requires reference value")
		}
	} else if value.Verifier != verifier {
		return fmt.Errorf("array store requires verifier type %d", verifier)
	}
	index, err := popValue(f, 1)
	if err != nil {
		return err
	}
	if index.Verifier != verifierInt {
		return fmt.Errorf("array index requires int verifier type")
	}
	array, err := popValue(f, 1)
	if err != nil {
		return err
	}
	if err := requireDereference(nil, array, "", "array store"); err != nil {
		return err
	}
	if array.LengthKnown {
		if offset, known := exactIntegerConstant(index); known && (offset < 0 || offset >= array.ArrayLength) {
			return &noNormalFlowError{}
		}
	}
	if err := validateArrayOpcode(op, array.Reference); err != nil {
		return err
	}
	if op == 0x53 && referenceArrayStoreDefinitelyFails(cf, array, value) {
		return &noNormalFlowError{}
	}
	exactIndex, indexKnown := exactIntegerConstant(index)
	strongUpdate := indexKnown && identityCount(array) == 1
	for i := 0; i < identityCount(array); i++ {
		key := arrayElementKey(identityAt(array, i))
		if indexKnown {
			key = arrayIndexedElementKey(identityAt(array, i), exactIndex)
		}
		storedValue := value
		if old, ok := f.Fields[key]; ok && !strongUpdate {
			merged, mergeErr := mergeValues(old, value, limits, budget)
			if mergeErr != nil {
				return mergeErr
			}
			storedValue = merged
		}
		if err := setFrameField(f, key, storedValue, limits, budget); err != nil {
			return err
		}
	}
	return nil
}

func referenceArrayStoreDefinitelyFails(cf *classModel, array, value abstractValue) bool {
	if isKnownNull(value) || !strings.HasPrefix(array.Reference, "[") || len(array.Reference) < 2 {
		return false
	}
	component := array.Reference[1:]
	if component[0] != 'L' && component[0] != '[' {
		return false
	}
	runtimeType := exactRuntimeType(value)
	if runtimeType == "" {
		return false
	}
	return !referenceAssignableTo(cf, runtimeType, descriptorReferenceName(component))
}

func arrayLoadType(op byte, arrayDescriptor string) (verifierType, string, uint8, error) {
	if err := validateArrayOpcode(op, arrayDescriptor); err != nil {
		return verifierTop, "", 0, err
	}
	switch op {
	case 0x2e, 0x33, 0x34, 0x35:
		return verifierInt, "", 1, nil
	case 0x2f:
		return verifierLong, "", 2, nil
	case 0x30:
		return verifierFloat, "", 1, nil
	case 0x31:
		return verifierDouble, "", 2, nil
	case 0x32:
		reference := ""
		if strings.HasPrefix(arrayDescriptor, "[") {
			component := arrayDescriptor[1:]
			if strings.HasPrefix(component, "L") && strings.HasSuffix(component, ";") {
				reference = component[1 : len(component)-1]
			} else if strings.HasPrefix(component, "[") {
				reference = component
			}
		}
		return verifierReference, reference, 1, nil
	default:
		return verifierTop, "", 0, fmt.Errorf("unsupported array load opcode")
	}
}

func arrayStoreType(op byte) (verifierType, uint8) {
	switch op {
	case 0x4f, 0x54, 0x55, 0x56:
		return verifierInt, 1
	case 0x50:
		return verifierLong, 2
	case 0x51:
		return verifierFloat, 1
	case 0x52:
		return verifierDouble, 2
	default:
		return verifierReference, 1
	}
}

func validateArrayOpcode(op byte, descriptor string) error {
	if descriptor == "" || descriptor == "java/lang/Object" || descriptor == "java/lang/Cloneable" || descriptor == "java/io/Serializable" {
		if descriptor == "" {
			return nil
		}
		return fmt.Errorf("array opcode 0x%02x requires an array, got %q", op, descriptor)
	}
	if descriptor == "[" {
		if op == 0x32 || op == 0x53 {
			return nil
		}
		return fmt.Errorf("primitive array opcode 0x%02x is incompatible with joined reference array", op)
	}
	valid := false
	switch op {
	case 0x2e, 0x4f:
		valid = descriptor == "[I"
	case 0x2f, 0x50:
		valid = descriptor == "[J"
	case 0x30, 0x51:
		valid = descriptor == "[F"
	case 0x31, 0x52:
		valid = descriptor == "[D"
	case 0x32, 0x53:
		valid = strings.HasPrefix(descriptor, "[[") || strings.HasPrefix(descriptor, "[L")
	case 0x33, 0x54:
		valid = descriptor == "[B" || descriptor == "[Z"
	case 0x34, 0x55:
		valid = descriptor == "[C"
	case 0x35, 0x56:
		valid = descriptor == "[S"
	}
	if !valid {
		return fmt.Errorf("array opcode 0x%02x is incompatible with %q", op, descriptor)
	}
	return nil
}

func arrayElementKey(id uint32) fieldKey {
	return fieldKey{ObjectID: id, Owner: "[", Name: "element", Descriptor: "*"}
}

func arrayIndexedElementKey(id uint32, index int64) fieldKey {
	return fieldKey{
		ObjectID: id, Owner: "[", Name: "element", Descriptor: "*",
		ArrayIndex: index, ArrayIndexKnown: true,
	}
}

func isArrayElementKey(key fieldKey, id uint32) bool {
	return key.ObjectID == id && key.Owner == "[" && key.Name == "element" && key.Descriptor == "*"
}

func transferStackOperation(op byte, f *frame, code *codeModel, limits Limits, budget *abstractBudget) error {
	s := f.Stack
	if op >= 0x59 && op <= 0x5e {
		start := len(s) - 4
		if start < 0 {
			start = 0
		}
		if err := budget.chargeValueCopies("stack duplication transient values", 0, s[start:], 2); err != nil {
			return err
		}
	}
	require := func(count int) error {
		if len(s) < count {
			return fmt.Errorf("operand stack underflow")
		}
		return nil
	}
	appendChecked := func(values ...abstractValue) error {
		f.Stack = append(f.Stack, values...)
		if stackSlots(f.Stack) > int(code.MaxStack) || len(f.Locals)+stackSlots(f.Stack)+len(f.Fields) > limits.MaxFrameSlots {
			return fmt.Errorf("operand stack exceeds declared or configured limit")
		}
		return nil
	}
	switch op {
	case 0x57:
		_, err := popValue(f, 1)
		return err
	case 0x58:
		if err := require(1); err != nil {
			return err
		}
		top := s[len(s)-1]
		if top.Width == 2 {
			f.Stack = s[:len(s)-1]
			return nil
		}
		if top.Width != 1 || len(s) < 2 || s[len(s)-2].Width != 1 {
			return fmt.Errorf("pop2 has impossible category-two shape")
		}
		f.Stack = s[:len(s)-2]
		return nil
	case 0x59:
		if err := require(1); err != nil || s[len(s)-1].Width != 1 {
			return fmt.Errorf("dup requires one category-one value")
		}
		return appendChecked(cloneValue(s[len(s)-1]))
	case 0x5a:
		if err := require(2); err != nil || s[len(s)-1].Width != 1 || s[len(s)-2].Width != 1 {
			return fmt.Errorf("dup_x1 requires two category-one values")
		}
		v1, v2 := cloneValue(s[len(s)-1]), cloneValue(s[len(s)-2])
		f.Stack = s[:len(s)-2]
		return appendChecked(v1, v2, cloneValue(v1))
	case 0x5b:
		if err := require(2); err != nil || s[len(s)-1].Width != 1 {
			return fmt.Errorf("dup_x2 requires a category-one top value")
		}
		v1 := cloneValue(s[len(s)-1])
		v2 := cloneValue(s[len(s)-2])
		if v2.Width == 2 {
			f.Stack = s[:len(s)-2]
			return appendChecked(v1, v2, cloneValue(v1))
		}
		if len(s) < 3 || v2.Width != 1 || s[len(s)-3].Width != 1 {
			return fmt.Errorf("dup_x2 has impossible category shape")
		}
		v3 := cloneValue(s[len(s)-3])
		f.Stack = s[:len(s)-3]
		return appendChecked(v1, v3, v2, cloneValue(v1))
	case 0x5c:
		if err := require(1); err != nil {
			return err
		}
		v1 := cloneValue(s[len(s)-1])
		if v1.Width == 2 {
			return appendChecked(cloneValue(v1))
		}
		if len(s) < 2 || v1.Width != 1 || s[len(s)-2].Width != 1 {
			return fmt.Errorf("dup2 has impossible category-two shape")
		}
		v2 := cloneValue(s[len(s)-2])
		return appendChecked(v2, v1)
	case 0x5d:
		if err := require(2); err != nil {
			return err
		}
		v1 := cloneValue(s[len(s)-1])
		v2 := cloneValue(s[len(s)-2])
		if v1.Width == 2 && v2.Width == 1 {
			f.Stack = s[:len(s)-2]
			return appendChecked(v1, v2, cloneValue(v1))
		}
		if v1.Width != 1 || v2.Width != 1 || len(s) < 3 || s[len(s)-3].Width != 1 {
			return fmt.Errorf("dup2_x1 has impossible category shape")
		}
		v3 := cloneValue(s[len(s)-3])
		f.Stack = s[:len(s)-3]
		return appendChecked(v2, v1, v3, cloneValue(v2), cloneValue(v1))
	case 0x5e:
		return transferDup2X2(f, code, limits)
	case 0x5f:
		if err := require(2); err != nil || s[len(s)-1].Width != 1 || s[len(s)-2].Width != 1 {
			return fmt.Errorf("swap requires two category-one values")
		}
		f.Stack[len(s)-1], f.Stack[len(s)-2] = f.Stack[len(s)-2], f.Stack[len(s)-1]
		return nil
	}
	return fmt.Errorf("unsupported stack operation")
}

func transferDup2X2(f *frame, code *codeModel, limits Limits) error {
	s := f.Stack
	if len(s) < 2 {
		return fmt.Errorf("dup2_x2 operand stack underflow")
	}
	v1, v2 := cloneValue(s[len(s)-1]), cloneValue(s[len(s)-2])
	var prefix []abstractValue
	var values []abstractValue
	switch {
	case v1.Width == 2 && v2.Width == 2:
		prefix = s[:len(s)-2]
		values = []abstractValue{v1, v2, cloneValue(v1)}
	case v1.Width == 2 && v2.Width == 1 && len(s) >= 3 && s[len(s)-3].Width == 1:
		v3 := cloneValue(s[len(s)-3])
		prefix = s[:len(s)-3]
		values = []abstractValue{v1, v3, v2, cloneValue(v1)}
	case v1.Width == 1 && v2.Width == 1 && len(s) >= 3 && s[len(s)-3].Width == 2:
		v3 := cloneValue(s[len(s)-3])
		prefix = s[:len(s)-3]
		values = []abstractValue{v2, v1, v3, cloneValue(v2), cloneValue(v1)}
	case v1.Width == 1 && v2.Width == 1 && len(s) >= 4 && s[len(s)-3].Width == 1 && s[len(s)-4].Width == 1:
		v3, v4 := cloneValue(s[len(s)-3]), cloneValue(s[len(s)-4])
		prefix = s[:len(s)-4]
		values = []abstractValue{v2, v1, v4, v3, cloneValue(v2), cloneValue(v1)}
	default:
		return fmt.Errorf("dup2_x2 has impossible category shape")
	}
	f.Stack = append(prefix, values...)
	if stackSlots(f.Stack) > int(code.MaxStack) || len(f.Locals)+stackSlots(f.Stack)+len(f.Fields) > limits.MaxFrameSlots {
		return fmt.Errorf("operand stack exceeds declared or configured limit")
	}
	return nil
}

func transferArithmetic(op byte, f *frame, push func(abstractValue) error, limits Limits, budget *abstractBudget) error {
	if op >= 0x74 && op <= 0x77 {
		width := []uint8{1, 2, 1, 2}[op-0x74]
		value, err := popValue(f, width)
		if err != nil {
			return err
		}
		want := []verifierType{verifierInt, verifierLong, verifierFloat, verifierDouble}[op-0x74]
		if value.Verifier != want {
			return fmt.Errorf("numeric negation requires verifier type %d", want)
		}
		value.Constant = ""
		return push(value)
	}
	if op >= 0x78 && op <= 0x7d {
		shift, err := popValue(f, 1)
		if err != nil {
			return err
		}
		if shift.Verifier != verifierInt {
			return fmt.Errorf("shift distance requires int verifier type")
		}
		width := uint8(1)
		if op == 0x79 || op == 0x7b || op == 0x7d {
			width = 2
		}
		value, err := popValue(f, width)
		if err != nil {
			return err
		}
		want := verifierInt
		if width == 2 {
			want = verifierLong
		}
		if value.Verifier != want {
			return fmt.Errorf("shift value requires verifier type %d", want)
		}
		value.Constant = ""
		return push(value)
	}
	width := uint8(1)
	if op <= 0x73 {
		if (op-0x60)%4 == 1 || (op-0x60)%4 == 3 {
			width = 2
		}
	} else if op == 0x7f || op == 0x81 || op == 0x83 {
		width = 2
	}
	right, err := popValue(f, width)
	if err != nil {
		return err
	}
	left, err := popValue(f, width)
	if err != nil {
		return err
	}
	want := arithmeticVerifier(op)
	if left.Verifier != want || right.Verifier != want {
		return fmt.Errorf("arithmetic opcode requires verifier type %d", want)
	}
	if op == 0x6c || op == 0x6d || op == 0x70 || op == 0x71 {
		if divisor, known := exactIntegerConstant(right); known && divisor == 0 {
			return &noNormalFlowError{}
		}
	}
	value, err := mergeValues(left, right, limits, budget)
	if err != nil {
		return err
	}
	value.Width = width
	value.Constant = ""
	return push(value)
}

func arithmeticVerifier(op byte) verifierType {
	if op >= 0x60 && op <= 0x73 {
		return []verifierType{verifierInt, verifierLong, verifierFloat, verifierDouble}[(op-0x60)%4]
	}
	if op == 0x7f || op == 0x81 || op == 0x83 {
		return verifierLong
	}
	return verifierInt
}

func verifierWidth(value verifierType) uint8 {
	if value == verifierLong || value == verifierDouble {
		return 2
	}
	return 1
}

func transferConversion(op byte, f *frame, push func(abstractValue) error) error {
	types := map[byte][2]verifierType{
		0x85: {verifierInt, verifierLong}, 0x86: {verifierInt, verifierFloat}, 0x87: {verifierInt, verifierDouble},
		0x88: {verifierLong, verifierInt}, 0x89: {verifierLong, verifierFloat}, 0x8a: {verifierLong, verifierDouble},
		0x8b: {verifierFloat, verifierInt}, 0x8c: {verifierFloat, verifierLong}, 0x8d: {verifierFloat, verifierDouble},
		0x8e: {verifierDouble, verifierInt}, 0x8f: {verifierDouble, verifierLong}, 0x90: {verifierDouble, verifierFloat},
		0x91: {verifierInt, verifierInt}, 0x92: {verifierInt, verifierInt}, 0x93: {verifierInt, verifierInt},
	}
	pair := types[op]
	value, err := popValue(f, verifierWidth(pair[0]))
	if err != nil {
		return err
	}
	if value.Verifier != pair[0] {
		return fmt.Errorf("conversion requires verifier type %d", pair[0])
	}
	value.Verifier = pair[1]
	value.Width = verifierWidth(pair[1])
	value.Constant = ""
	return push(value)
}

func transferComparison(op byte, f *frame, push func(abstractValue) error) error {
	width := uint8(1)
	if op == 0x94 || op == 0x97 || op == 0x98 {
		width = 2
	}
	right, err := popValue(f, width)
	if err != nil {
		return err
	}
	left, err := popValue(f, width)
	if err != nil {
		return err
	}
	want := verifierFloat
	if op == 0x94 {
		want = verifierLong
	} else if op == 0x97 || op == 0x98 {
		want = verifierDouble
	}
	if left.Verifier != want || right.Verifier != want {
		return fmt.Errorf("comparison requires verifier type %d", want)
	}
	return push(abstractValue{Kinds: kindUnknown, Verifier: verifierInt, Width: 1})
}

func transferReturn(op byte, cf *classModel, method *methodModel, f *frame, analysis *methodAnalysis) error {
	parsed, err := parseMethodDescriptor(method.Descriptor)
	if err != nil {
		return err
	}
	if op == 0xb1 {
		if !parsed.Return.Void {
			return fmt.Errorf("void return for non-void descriptor")
		}
		if method.Name == "<init>" && f.ThisUninit {
			return fmt.Errorf("constructor returns before initializing this")
		}
		return nil
	}
	wantOpcode := map[byte]byte{'B': 0xac, 'C': 0xac, 'I': 0xac, 'S': 0xac, 'Z': 0xac,
		'F': 0xae, 'J': 0xad, 'D': 0xaf, 'L': 0xb0, '[': 0xb0}[parsed.Return.Descriptor[0]]
	if parsed.Return.Void || op != wantOpcode {
		return fmt.Errorf("return opcode is incompatible with method descriptor")
	}
	value, err := popValue(f, parsed.Return.Width)
	if err != nil {
		return err
	}
	if !valueAssignmentCompatible(cf, value, parsed.Return) {
		return fmt.Errorf("return value is incompatible with method descriptor")
	}
	if analysis.summarizing && !f.Unproven {
		analysis.Summary.ReturnFromArgs = analysis.Summary.ReturnFromArgs.union(value.Arguments)
		analysis.Summary.ReturnTaint |= value.Taint
		analysis.Summary.ReturnKinds |= value.Kinds
		if !analysis.returnSeen {
			analysis.Summary.Constant = value.Constant
		} else if analysis.Summary.Constant != value.Constant {
			analysis.Summary.Constant = ""
		}
		analysis.returnSeen = true
	}
	return nil
}

func transferField(
	cf *classModel,
	method *methodModel,
	ins instruction,
	f *frame,
	push func(abstractValue) error,
	limits Limits,
	budget *abstractBudget,
) error {
	ref, err := resolveFieldOperand(cf, ins)
	if err != nil {
		return err
	}
	typeInfo, err := parseFieldDescriptor(ref.Descriptor)
	if err != nil {
		return fmt.Errorf("field descriptor: %w", err)
	}
	if err := validateCurrentFieldForm(cf, method, ref, ins.Opcode); err != nil {
		return err
	}
	if cf == nil || ref.Owner != cf.Name {
		f.Unproven = true
	}
	switch ins.Opcode {
	case 0xb2:
		key := fieldKey{ObjectID: staticObjectID, Owner: ref.Owner, Name: ref.Name, Descriptor: ref.Descriptor}
		value, ok := f.Fields[key]
		if !ok {
			value = seededFieldValue(cf, ref, typeInfo, limits)
		}
		return push(value)
	case 0xb3:
		value, err := popValue(f, typeInfo.Width)
		if err != nil {
			return err
		}
		if !valueAssignmentCompatible(cf, value, typeInfo) {
			return fmt.Errorf("putstatic value is incompatible with field descriptor")
		}
		return setFrameField(f, fieldKey{ObjectID: staticObjectID, Owner: ref.Owner, Name: ref.Name, Descriptor: ref.Descriptor}, value, limits, budget)
	case 0xb4:
		receiver, err := popValue(f, 1)
		if err != nil {
			return err
		}
		if err := requireDereference(cf, receiver, ref.Owner, "getfield"); err != nil {
			return err
		}
		value := valueForDescriptor(typeInfo)
		for i := 0; i < identityCount(receiver); i++ {
			if stored, ok := f.Fields[fieldKey{ObjectID: identityAt(receiver, i), Owner: ref.Owner, Name: ref.Name, Descriptor: ref.Descriptor}]; ok {
				value, err = mergeValues(value, stored, limits, budget)
				if err != nil {
					return err
				}
			}
		}
		return push(value)
	case 0xb5:
		value, err := popValue(f, typeInfo.Width)
		if err != nil {
			return err
		}
		if !valueAssignmentCompatible(cf, value, typeInfo) {
			return fmt.Errorf("putfield value is incompatible with field descriptor")
		}
		receiver, err := popValue(f, 1)
		if err != nil {
			return err
		}
		if err := requireDereference(cf, receiver, ref.Owner, "putfield"); err != nil {
			return err
		}
		for i := 0; i < identityCount(receiver); i++ {
			if err := setFrameField(f, fieldKey{ObjectID: identityAt(receiver, i), Owner: ref.Owner, Name: ref.Name, Descriptor: ref.Descriptor}, value, limits, budget); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unsupported field opcode")
}

func validateCurrentFieldForm(cf *classModel, method *methodModel, ref memberReference, opcode byte) error {
	if cf == nil || ref.Owner != cf.Name {
		return nil
	}
	var field *fieldModel
	for index := range cf.Fields {
		candidate := &cf.Fields[index]
		if candidate.Name == ref.Name && candidate.Descriptor == ref.Descriptor {
			field = candidate
			break
		}
	}
	if field == nil {
		return fmt.Errorf("current-class field %s.%s%s is not declared", ref.Owner, ref.Name, ref.Descriptor)
	}
	staticOpcode := opcode == 0xb2 || opcode == 0xb3
	staticField := field.Access&0x0008 != 0
	if staticOpcode != staticField {
		return fmt.Errorf("field %s.%s static form does not match opcode 0x%02x", ref.Owner, ref.Name, opcode)
	}
	write := opcode == 0xb3 || opcode == 0xb5
	if !write || field.Access&0x0010 == 0 {
		return nil
	}
	if staticField && method.Name != "<clinit>" {
		return fmt.Errorf("final static field %s.%s may only be written in <clinit>", ref.Owner, ref.Name)
	}
	if !staticField && method.Name != "<init>" {
		return fmt.Errorf("final instance field %s.%s may only be written in <init>", ref.Owner, ref.Name)
	}
	return nil
}

func transferInvoke(
	cf *classModel,
	ins instruction,
	f *frame,
	analysis *methodAnalysis,
	code *codeModel,
	opts Options,
	budget *abstractBudget,
) error {
	static := ins.Opcode == 0xb8 || ins.Opcode == 0xba
	var (
		ref        memberReference
		dynamic    invokeDynamicReference
		bootstrap  *bootstrapMethod
		descriptor string
		name       string
		err        error
	)
	if ins.Opcode == 0xba {
		if len(ins.Operands) != 4 {
			return fmt.Errorf("invalid invokedynamic operands")
		}
		dynamicIndex := binary.BigEndian.Uint16(ins.Operands[:2])
		dynamicReference, dynamicErr := cf.invokeDynamic(dynamicIndex)
		if dynamicErr != nil {
			return dynamicErr
		}
		if int(dynamicIndex) < len(cf.BootstrapFailures) && cf.BootstrapFailures[dynamicIndex] {
			return &noNormalFlowError{}
		}
		dynamic = dynamicReference
		if int(dynamic.Bootstrap) < len(cf.Bootstraps) {
			bootstrap = &cf.Bootstraps[dynamic.Bootstrap]
		}
		name, descriptor = dynamic.Name, dynamic.Descriptor
	} else {
		ref, err = resolveInvokeOperand(cf, ins)
		if err != nil {
			return err
		}
		name, descriptor = ref.Name, ref.Descriptor
	}
	if err := validateInvokeLegality(cf, ins.Opcode, ref, name, descriptor); err != nil {
		return err
	}
	if static && modeledInstanceAPI(ref) {
		return fmt.Errorf("instance API %s.%s cannot be invoked statically", ref.Owner, ref.Name)
	}
	if !static && ref.Owner == "java/lang/Runtime" && ref.Name == "getRuntime" &&
		ref.Descriptor == "()Ljava/lang/Runtime;" {
		return fmt.Errorf("Runtime.getRuntime requires invokestatic")
	}
	if ins.Opcode == 0xba {
		if !trustedBootstrap(bootstrap) {
			f.Unproven = true
		}
	}
	parsed, err := parseMethodDescriptor(descriptor)
	if err != nil {
		return fmt.Errorf("invoke descriptor: %w", err)
	}
	dynamicLinkageTrusted := false
	if ins.Opcode == 0xba {
		trusted, trustErr := trustedInvokeDynamicLinkage(cf, dynamic, bootstrap, parsed, analysis.summaries)
		if trustErr != nil {
			return trustErr
		}
		dynamicLinkageTrusted = trusted
		if !trusted {
			f.Unproven = true
		}
	}
	if !static && parsed.ParameterSlots+1 > maxJVMParameterSlots {
		return fmt.Errorf("invoke receiver and parameters exceed JVM slot limit")
	}
	if ins.Opcode == 0xb9 && int(ins.Operands[2]) != parsed.ParameterSlots+1 {
		return fmt.Errorf("invokeinterface count %d does not match %d slots", ins.Operands[2], parsed.ParameterSlots+1)
	}
	if err := budget.charge("invoke argument vector", len(parsed.Parameters)); err != nil {
		return err
	}
	args := make([]abstractValue, len(parsed.Parameters))
	for index := len(parsed.Parameters) - 1; index >= 0; index-- {
		args[index], err = popValue(f, parsed.Parameters[index].Width)
		if err != nil {
			return fmt.Errorf("argument %d: %w", index, err)
		}
		if !valueAssignmentCompatible(cf, args[index], parsed.Parameters[index]) {
			return fmt.Errorf("argument %d is incompatible with descriptor %s", index, parsed.Parameters[index].Descriptor)
		}
	}
	var receiver abstractValue
	if !static {
		receiver, err = popValue(f, 1)
		if err != nil {
			return fmt.Errorf("receiver: %w", err)
		}
		if name == "<init>" {
			if receiver.Verifier != verifierUninitialized {
				return fmt.Errorf("constructor receiver must be uninitialized")
			}
			if !constructorReceiverMatches(cf, receiver, ref.Owner) {
				return fmt.Errorf("uninitialized %q cannot invoke constructor %s", receiver.Reference, ref.Owner)
			}
			if err := initializeAllocationAliases(f, receiver, budget); err != nil {
				return err
			}
			if receiver.ObjectID == receiverObjectID {
				f.ThisUninit = false
			}
			receiver.Verifier = verifierReference
		} else {
			if err := requireDereference(cf, receiver, ref.Owner, "invoke"); err != nil {
				return err
			}
			if trustedInvocation(cf, ref) {
				switch modeledReceiverShapeStatus(cf, receiver, ref) {
				case receiverShapeTrusted:
				case receiverShapeUnproven:
					f.Unproven = true
				case receiverShapeInvalid:
					return fmt.Errorf("modeled API %s.%s receiver %q is not trusted", ref.Owner, ref.Name, receiver.Reference)
				}
			}
		}
	}

	combined, err := combineSemanticValues(receiver, args, opts.Limits, budget)
	if err != nil {
		return err
	}
	localSummary, summaryInputs, localCall := invocationSummary(ins.Opcode, ref, receiver, args, f, analysis.summaries, opts.Limits)
	if ins.Opcode != 0xba && !trustedInvocation(cf, ref) && !localCall {
		f.Unproven = true
	}
	if ins.Opcode == 0xba {
		result, handled, dynamicErr := modelInvokeDynamic(dynamic, bootstrap, args, parsed, ins, dynamicLinkageTrusted, f, opts, budget)
		if dynamicErr != nil {
			return dynamicErr
		}
		if handled {
			if parsed.Return.Void {
				return nil
			}
			if err := budget.chargeValueCopies("invokedynamic result stack retention", 0, []abstractValue{result}, 1); err != nil {
				return err
			}
			return pushValue(f, result, code, opts.Limits)
		}
	} else if err := modelInvokeSideEffectsAndSinks(cf, ref, receiver, args, parsed, ins, f, analysis, opts, budget); err != nil {
		return err
	}
	if localCall {
		if err := applySummarySinks(localSummary, summaryInputs, ref, ins, f, analysis, opts, budget); err != nil {
			return err
		}
		if parsed.Return.Void {
			return nil
		}
		result, err := summaryReturnValue(localSummary, summaryInputs, parsed.Return, ref, ins, opts, budget)
		if err != nil {
			return err
		}
		return pushValue(f, result, code, opts.Limits)
	}
	if parsed.Return.Void {
		return nil
	}
	if result, handled, modelErr := modelInvokeResult(ref, receiver, args, parsed, ins, f, opts, budget); handled || modelErr != nil {
		if modelErr != nil {
			return modelErr
		}
		if err := budget.chargeValueCopies("modeled invoke result stack retention", 0, []abstractValue{result}, 1); err != nil {
			return err
		}
		return pushValue(f, result, code, opts.Limits)
	}
	result := valueForDescriptor(parsed.Return)
	if ref.Owner == "java/lang/Runtime" && ref.Name == "getRuntime" && ref.Descriptor == "()Ljava/lang/Runtime;" {
		result.RuntimeType = "java/lang/Runtime"
		result.Nullness = nullnessNonNull
	}
	result.Taint = combined.Taint
	if err := budget.chargeValueCopies("invoke result provenance", 0, []abstractValue{{Provenance: combined.Provenance}}, 1); err != nil {
		return err
	}
	result.Provenance = cloneProvenance(combined.Provenance)
	result.Constant = ""
	if requestSourceAPIs.matches(ref) {
		if err := budget.charge("modeled request source provenance", 1); err != nil {
			return err
		}
		result.Taint = requestSourceTaint(ref)
		result.Provenance = appendProvenance(nil, provenanceStep{Offset: ins.Offset, API: shortAPI(ref)}, opts.Limits.MaxProvenanceSteps)
	}
	if sessionAttributeSourceAPIs.matches(ref) {
		if err := budget.charge("modeled session source provenance", 1); err != nil {
			return err
		}
		result.Taint = taintSession
		result.Provenance = appendProvenance(nil, provenanceStep{Offset: ins.Offset, API: shortAPI(ref)}, opts.Limits.MaxProvenanceSteps)
	}
	if applicationAttributeSourceAPIs.matches(ref) {
		if err := budget.charge("modeled application source provenance", 1); err != nil {
			return err
		}
		result.Taint = taintApplication
		result.Provenance = appendProvenance(nil, provenanceStep{Offset: ins.Offset, API: shortAPI(ref)}, opts.Limits.MaxProvenanceSteps)
	}
	if pageContextRequestAPIs.matches(ref) {
		if err := budget.charge("modeled request alias provenance", 1); err != nil {
			return err
		}
		result.Taint = taintRequestParameter | taintRequestHeader | taintRequestBody | taintCookie
		result.Provenance = appendProvenance(nil, provenanceStep{Offset: ins.Offset, API: shortAPI(ref)}, opts.Limits.MaxProvenanceSteps)
	}
	if err := budget.chargeValueCopies("invoke result stack retention", 0, []abstractValue{result}, 1); err != nil {
		return err
	}
	return pushValue(f, result, code, opts.Limits)
}

type summaryInputs map[int]abstractValue

func invocationSummary(
	opcode byte,
	ref memberReference,
	receiver abstractValue,
	args []abstractValue,
	f *frame,
	summaries summarySet,
	limits Limits,
) (methodSummary, summaryInputs, bool) {
	if len(summaries) == 0 {
		return methodSummary{}, nil, false
	}
	if opcode == 0xb9 {
		if summary, inputs, ok := lambdaInvocationSummary(ref, receiver, args, f, summaries, limits); ok {
			return summary, inputs, true
		}
	}
	key := summaryKey{Method: methodKey{Owner: ref.Owner, Name: ref.Name, Descriptor: ref.Descriptor}, Namespace: summaryExact}
	if opcode == 0xb6 || opcode == 0xb9 {
		key.Namespace = summaryVirtual
	}
	summary, ok := summaries[key]
	if !ok {
		return methodSummary{}, nil, false
	}
	inputs := make(summaryInputs)
	local := 0
	if opcode != 0xb8 {
		inputs[0] = receiver
		local = 1
	}
	descriptor, err := parseMethodDescriptor(ref.Descriptor)
	if err != nil {
		return methodSummary{}, nil, false
	}
	for index, parameter := range descriptor.Parameters {
		inputs[local] = args[index]
		local += int(parameter.Width)
	}
	return summary, inputs, true
}

func lambdaInvocationSummary(
	ref memberReference,
	receiver abstractValue,
	args []abstractValue,
	f *frame,
	summaries summarySet,
	limits Limits,
) (methodSummary, summaryInputs, bool) {
	shape, ok := supportedLambdaSAMShapes[receiver.Reference]
	if !ok || ref.Name != shape.Method || ref.Descriptor != shape.Descriptor {
		return methodSummary{}, nil, false
	}
	var result methodSummary
	inputs := make(summaryInputs)
	targets := 0
	for identityIndex := 0; identityIndex < identityCount(receiver); identityIndex++ {
		object, found := f.Heap[identityAt(receiver, identityIndex)]
		if !found {
			continue
		}
		for _, callable := range object.Lambda {
			summary, found := summaries[exactSummaryKey(methodKey{
				Owner: callable.Target.Owner, Name: callable.Target.Name, Descriptor: callable.Target.Descriptor,
			})]
			if !found {
				continue
			}
			targets++
			if targets > limits.MaxCallTargets {
				return methodSummary{}, nil, false
			}
			if targets == 1 {
				result = summary
			} else {
				result = mergeMethodSummaries(result, summary)
			}
			values := append(append([]abstractValue(nil), callable.Captured...), args...)
			descriptor, err := parseMethodDescriptor(callable.Target.Descriptor)
			if err != nil || len(values) != len(descriptor.Parameters) {
				continue
			}
			local := 0
			for index, parameter := range descriptor.Parameters {
				inputs[local] = mergeSummaryInput(inputs[local], values[index], limits)
				local += int(parameter.Width)
			}
		}
	}
	return result, inputs, targets != 0
}

func mergeSummaryInput(left, right abstractValue, limits Limits) abstractValue {
	if left.Width == 0 {
		return cloneValue(right)
	}
	summaryOnly := mergedSummaryOnly(left, right)
	left.Taint |= right.Taint
	left.Arguments = left.Arguments.union(right.Arguments)
	left.Kinds |= right.Kinds
	left.SummaryOnly = summaryOnly
	left.Constant = ""
	left.Provenance = mergeProvenance(left.Provenance, right.Provenance, limits.MaxProvenanceSteps)
	return left
}

func summaryInputValue(bits argumentSet, inputs summaryInputs, limits Limits, budget *abstractBudget) (abstractValue, error) {
	var result abstractValue
	for slot := 0; slot < maxJVMParameterSlots+1; slot++ {
		if !bits.has(slot) {
			continue
		}
		value, ok := inputs[slot]
		if !ok {
			continue
		}
		var err error
		result, err = mergeSemanticValues(result, value, limits, budget)
		if err != nil {
			return abstractValue{}, err
		}
	}
	return result, nil
}

func applySummarySinks(
	summary methodSummary,
	inputs summaryInputs,
	ref memberReference,
	ins instruction,
	f *frame,
	analysis *methodAnalysis,
	opts Options,
	budget *abstractBudget,
) error {
	if f.Unproven {
		return nil
	}
	for _, kind := range orderedSemanticSinkKinds() {
		value, err := summaryInputValue(summary.SinkFromArgs[kind], inputs, opts.Limits, budget)
		if err != nil {
			return err
		}
		value.Taint |= summary.SinkTaint[kind]
		if !executionInput(value, analysis) {
			continue
		}
		value.Provenance = appendProvenance(value.Provenance, provenanceStep{Offset: ins.Offset, API: shortAPI(ref)}, opts.Limits.MaxProvenanceSteps)
		if err := recordSink(analysis, kind, 75, value, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
			return err
		}
	}
	return nil
}

func summaryReturnValue(
	summary methodSummary,
	inputs summaryInputs,
	returnType descriptorType,
	ref memberReference,
	ins instruction,
	opts Options,
	budget *abstractBudget,
) (abstractValue, error) {
	result := valueForDescriptor(returnType)
	mapped, err := summaryInputValue(summary.ReturnFromArgs, inputs, opts.Limits, budget)
	if err != nil {
		return abstractValue{}, err
	}
	result.Taint = mapped.Taint | summary.ReturnTaint
	result.Arguments = mapped.Arguments
	result.Kinds |= mapped.Kinds | summary.ReturnKinds
	result.Constant = summary.Constant
	result.SummaryOnly = result.Taint != 0
	result.Provenance = appendProvenance(mapped.Provenance, provenanceStep{Offset: ins.Offset, API: shortAPI(ref)}, opts.Limits.MaxProvenanceSteps)
	return result, nil
}

func combineSemanticValues(receiver abstractValue, args []abstractValue, limits Limits, budget *abstractBudget) (abstractValue, error) {
	combined := receiver
	if combined.Width == 0 {
		combined = unknownValue(1)
	}
	var err error
	for _, arg := range args {
		combined, err = mergeSemanticValues(combined, arg, limits, budget)
		if err != nil {
			return abstractValue{}, err
		}
	}
	return combined, nil
}

func modelInvokeDynamic(
	dynamic invokeDynamicReference,
	bootstrap *bootstrapMethod,
	args []abstractValue,
	parsed methodDescriptor,
	ins instruction,
	linkageTrusted bool,
	f *frame,
	opts Options,
	budget *abstractBudget,
) (abstractValue, bool, error) {
	if bootstrap == nil {
		return abstractValue{}, false, nil
	}
	switch {
	case isStringConcatBootstrap(bootstrap):
		result := valueForDescriptor(parsed.Return)
		result.Kinds |= kindString
		result, err := deriveModeledResult(result, args, provenanceStep{Offset: ins.Offset, API: shortAPI(bootstrap.Handle)}, opts.Limits, budget)
		if err != nil {
			return abstractValue{}, false, err
		}
		if constant, ok := invokeDynamicConcatConstant(bootstrap, args, opts.Limits); ok {
			result.Constant = constant
		}
		return result, true, nil
	case isLambdaMetafactoryBootstrap(bootstrap):
		result := valueForDescriptor(parsed.Return)
		result.ObjectID = allocationObjectID(ins.Offset)
		result.Nullness = nullnessNonNull
		semantic, err := combineSemanticValues(abstractValue{}, args, opts.Limits, budget)
		if err != nil {
			return abstractValue{}, false, err
		}
		result.Taint = semantic.Taint
		result.SummaryOnly = semantic.SummaryOnly
		result.Provenance = cloneProvenance(semantic.Provenance)
		if linkageTrusted {
			target, ok := lambdaTarget(bootstrap)
			if !ok {
				return result, true, nil
			}
			captured := make([]abstractValue, len(args))
			for index := range args {
				captured[index] = cloneValue(args[index])
			}
			object := heapObject{Lambda: []lambdaValue{{Target: target, Captured: captured}}}
			if err := setHeapObject(f, result.ObjectID, object, opts.Limits, budget); err != nil {
				return abstractValue{}, false, err
			}
		}
		return result, true, nil
	default:
		_ = dynamic
		return abstractValue{}, false, nil
	}
}

func modelInvokeSideEffectsAndSinks(
	cf *classModel,
	ref memberReference,
	receiver abstractValue,
	args []abstractValue,
	parsed methodDescriptor,
	ins instruction,
	f *frame,
	analysis *methodAnalysis,
	opts Options,
	budget *abstractBudget,
) error {
	if ref.Name == "<init>" && isModeledConstructor(ref) {
		if err := modelConstructorHeap(ref, receiver, args, f, opts.Limits, budget); err != nil {
			return err
		}
	}
	if isBuilderAppend(ref) {
		if err := mergeHeapSlot(receiver, f, opts.Limits, budget, func(object *heapObject, value abstractValue) {
			object.Builder = value
		}, heapObject{Builder: firstArg(args)}); err != nil {
			return err
		}
	}
	if isStreamWrite(ref) {
		written, err := resolveWrittenValue(args, f, opts.Limits, budget)
		if err != nil {
			return err
		}
		if err := mergeHeapSlot(receiver, f, opts.Limits, budget, func(object *heapObject, value abstractValue) {
			object.Stream = value
		}, heapObject{Stream: written}); err != nil {
			return err
		}
		if err := propagateStreamWriteToDelegates(receiver, written, f, opts.Limits, budget); err != nil {
			return err
		}
		if !f.Unproven && executionInput(written, analysis) {
			if path, ok, pathErr := receiverExecutablePath(receiver, f, opts, budget); pathErr != nil {
				return pathErr
			} else if ok && dangerousExecutableDestination(path, opts) {
				if err := recordSink(analysis, sinkExecutableWrite, 85, written, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
					return err
				}
			}
		}
	}
	if isCollectionMutation(ref) {
		if err := modelCollectionMutation(ref, receiver, args, f, opts.Limits, budget); err != nil {
			return err
		}
	}
	if processBuilderConstructorAPIs.matches(ref) && valueHasExactReference(receiver, "java/lang/ProcessBuilder") && len(args) != 0 {
		for i := 0; i < identityCount(receiver); i++ {
			if err := setFrameField(f, processBuilderCommandKey(identityAt(receiver, i)), args[0], opts.Limits, budget); err != nil {
				return err
			}
		}
	}
	if !f.Unproven && runtimeExecAPIs.matches(ref) && valueHasExactReference(receiver, "java/lang/Runtime") &&
		len(parsed.Parameters) != 0 && len(args) != 0 {
		commandArgument, err := resolveCommandValue(args[0], f, opts.Limits, budget)
		if err != nil {
			return err
		}
		if valueHasExactDescriptor(commandArgument, parsed.Parameters[0]) && executionInput(commandArgument, analysis) {
			if err := recordExecution(analysis, commandArgument, ins.Offset, "Runtime.exec", opts.Limits, budget); err != nil {
				return err
			}
		}
	}
	if !f.Unproven && processBuilderStartAPIs.matches(ref) && valueHasExactReference(receiver, "java/lang/ProcessBuilder") {
		command, found, err := processBuilderCommand(receiver, f, opts.Limits, budget)
		if err != nil {
			return err
		}
		if found && executionInput(command, analysis) {
			if err := recordExecution(analysis, command, ins.Offset, "ProcessBuilder.start", opts.Limits, budget); err != nil {
				return err
			}
		}
	}
	if !f.Unproven && (classDefinitionAPIs.matches(ref) || isInheritedClassDefinition(cf, ref)) {
		if payload, ok, err := classloadPayload(args, f, opts.Limits, budget); err != nil {
			return err
		} else if ok && executionInput(payload, analysis) {
			if err := recordSink(analysis, sinkDynamicLoad, 85, payload, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
				return err
			}
		}
	}
	if !f.Unproven && scriptEvaluationAPIs.matches(ref) && len(args) != 0 {
		script, err := resolveCommandValue(args[0], f, opts.Limits, budget)
		if err != nil {
			return err
		}
		if executionInput(script, analysis) {
			if err := recordSink(analysis, sinkScriptEval, 85, script, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
				return err
			}
		}
	}
	if !f.Unproven && executableWriteAPIs.matches(ref) {
		if err := modelExecutableWrite(ref, args, ins, f, analysis, opts, budget); err != nil {
			return err
		}
	}
	if !f.Unproven && reflectionExecutionAPIs.matches(ref) {
		reflected, err := resolveWrittenValue(args, f, opts.Limits, budget)
		if err != nil {
			return err
		}
		if executionInput(reflected, analysis) {
			if err := recordSink(analysis, sinkReflection, 85, reflected, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
				return err
			}
		}
	}
	if jndiLookupAPIs.matches(ref) && len(args) != 0 {
		name, err := resolveCommandValue(args[0], f, opts.Limits, budget)
		if err != nil {
			return err
		}
		switch {
		case !f.Unproven && executionInput(name, analysis):
			if err := recordSink(analysis, sinkDeserializationJNDI, 75, name, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
				return err
			}
		case isRemoteJNDI(name.Constant):
			if err := recordSink(analysis, sinkDeserializationJNDI, 60, name, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
				return err
			}
		}
	}
	if !f.Unproven && deserializationAPIs.matches(ref) {
		input, err := resolveCommandValue(receiver, f, opts.Limits, budget)
		if err != nil {
			return err
		}
		if executionInput(input, analysis) {
			if err := recordSink(analysis, sinkDeserializationJNDI, 75, input, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
				return err
			}
		}
	}
	if hookRegistrationAPIs.matches(ref) {
		hookValue, err := hookRegistrationCodeValue(ref, args, f, opts.Limits, budget)
		if err != nil {
			return err
		}
		score := 60
		if !f.Unproven && executionInput(hookValue, analysis) {
			score = 75
		}
		if err := recordSink(analysis, sinkHookRegistration, score, hookValue, ins.Offset, shortAPI(ref), opts.Limits, budget); err != nil {
			return err
		}
	}
	return nil
}

func modelInvokeResult(
	ref memberReference,
	receiver abstractValue,
	args []abstractValue,
	parsed methodDescriptor,
	ins instruction,
	f *frame,
	opts Options,
	budget *abstractBudget,
) (abstractValue, bool, error) {
	step := provenanceStep{Offset: ins.Offset, API: shortAPI(ref)}
	switch {
	case isBuilderAppend(ref), isStreamWrite(ref):
		return cloneValue(receiver), true, nil
	case isBuilderResult(ref):
		result := valueForDescriptor(parsed.Return)
		result.Kinds |= kindString
		return resultFromHeap(result, receiver, f, opts.Limits, budget, step, func(object heapObject) []abstractValue {
			return []abstractValue{object.Builder}
		})
	case isStreamResult(ref), isCompressionTransform(ref):
		result := valueForDescriptor(parsed.Return)
		if parsed.Return.Descriptor == "[B" {
			result.Kinds |= kindBytes
		} else if parsed.Return.Descriptor == "Ljava/lang/String;" {
			result.Kinds |= kindString
		}
		return resultFromHeap(result, receiver, f, opts.Limits, budget, step, func(object heapObject) []abstractValue {
			return []abstractValue{object.Stream}
		})
	case isCollectionRead(ref):
		result := valueForDescriptor(parsed.Return)
		value, found, err := collectionReadValue(ref, receiver, args, f, opts.Limits, budget)
		if err != nil || !found {
			return abstractValue{}, found, err
		}
		result, err = deriveModeledResult(result, []abstractValue{value}, step, opts.Limits, budget)
		return result, true, err
	case stringTransformAPIs.matches(ref):
		result := valueForDescriptor(parsed.Return)
		if parsed.Return.Descriptor == "[B" {
			result.Kinds |= kindBytes
		} else {
			result.Kinds |= kindString
		}
		sources := append([]abstractValue{receiver}, args...)
		if ref.Name == "valueOf" || ref.Name == "copyValueOf" {
			sources = args
		}
		if ref.Name == "getBytes" {
			sources = []abstractValue{receiver}
		}
		var err error
		result, err = deriveModeledResult(result, sources, step, opts.Limits, budget)
		if err != nil {
			return abstractValue{}, true, err
		}
		if ref.Name == "concat" {
			if constant, ok := concatConstants(sources, opts.Limits); ok {
				result.Constant = constant
			}
		} else if len(sources) == 1 && len(sources[0].Constant) <= opts.Limits.MaxConstantBytes {
			result.Constant = sources[0].Constant
		}
		return result, true, nil
	case base64DecodeAPIs.matches(ref), hexDecodeAPIs.matches(ref), urlDecodeAPIs.matches(ref):
		result := valueForDescriptor(parsed.Return)
		if parsed.Return.Descriptor == "[B" {
			result.Kinds |= kindBytes | kindClassBytes
		} else {
			result.Kinds |= kindString
		}
		source := firstArg(args)
		var err error
		result, err = deriveModeledResult(result, []abstractValue{source}, step, opts.Limits, budget)
		if err != nil {
			return abstractValue{}, true, err
		}
		if constant, ok := decodeConstantTransform(ref, source.Constant, opts.Limits); ok {
			result.Constant = constant
		}
		return result, true, nil
	case pathTransformAPIs.matches(ref):
		result := valueForDescriptor(parsed.Return)
		result.Kinds |= kindPath
		var err error
		result, err = deriveModeledResult(result, args, step, opts.Limits, budget)
		if err != nil {
			return abstractValue{}, true, err
		}
		if constant, ok, pathErr := exactPathTransformConstant(args, f, opts.Limits, budget); pathErr != nil {
			return abstractValue{}, true, pathErr
		} else if ok {
			result.Constant = constant
		}
		return result, true, nil
	case responseAccessAPIs.matches(ref):
		result := valueForDescriptor(parsed.Return)
		result.ObjectID = allocationObjectID(ins.Offset)
		result.Nullness = nullnessNonNull
		if err := setHeapObject(f, result.ObjectID, heapObject{}, opts.Limits, budget); err != nil {
			return abstractValue{}, true, err
		}
		return result, true, nil
	case executableWriteAPIs.matches(ref) && ref.Name == "newOutputStream":
		result := valueForDescriptor(parsed.Return)
		result.ObjectID = allocationObjectID(ins.Offset)
		result.Nullness = nullnessNonNull
		object := heapObject{Builder: firstArg(args)}
		if err := setHeapObject(f, result.ObjectID, object, opts.Limits, budget); err != nil {
			return abstractValue{}, true, err
		}
		return result, true, nil
	default:
		return abstractValue{}, false, nil
	}
}

func deriveModeledResult(
	base abstractValue,
	sources []abstractValue,
	step provenanceStep,
	limits Limits,
	budget *abstractBudget,
) (abstractValue, error) {
	semantic, err := combineSemanticValues(abstractValue{}, sources, limits, budget)
	if err != nil {
		return abstractValue{}, err
	}
	base.Taint = semantic.Taint
	base.Kinds |= semantic.Kinds
	base.Arguments = semantic.Arguments
	base.SummaryOnly = semantic.SummaryOnly
	base.Constant = ""
	base.Provenance = appendProvenance(semantic.Provenance, step, limits.MaxProvenanceSteps)
	return base, nil
}

func firstArg(args []abstractValue) abstractValue {
	if len(args) == 0 {
		return abstractValue{}
	}
	return args[0]
}

func trustedBootstrap(bootstrap *bootstrapMethod) bool {
	return isStringConcatBootstrap(bootstrap) || isLambdaMetafactoryBootstrap(bootstrap)
}

func trustedInvokeDynamicLinkage(
	cf *classModel,
	dynamic invokeDynamicReference,
	bootstrap *bootstrapMethod,
	parsed methodDescriptor,
	summaries summarySet,
) (bool, error) {
	if !trustedBootstrap(bootstrap) {
		return false, nil
	}
	switch {
	case isStringConcatBootstrap(bootstrap):
		return validStringConcatLinkage(bootstrap, parsed), nil
	case isLambdaMetafactoryBootstrap(bootstrap):
		return validLambdaMetafactoryLinkage(cf, dynamic, bootstrap, parsed, summaries)
	default:
		return false, nil
	}
}

func validStringConcatLinkage(bootstrap *bootstrapMethod, parsed methodDescriptor) bool {
	if bootstrap == nil || parsed.Return.Descriptor != "Ljava/lang/String;" {
		return false
	}
	switch bootstrap.Handle.Name {
	case "makeConcat":
		return len(bootstrap.Arguments) == 0
	case "makeConcatWithConstants":
		if len(bootstrap.Arguments) == 0 || bootstrap.Arguments[0].Kind != constantString {
			return false
		}
		argMarkers, constMarkers := concatRecipeMarkerCounts(bootstrap.Arguments[0].String)
		if argMarkers != len(parsed.Parameters) || constMarkers != len(bootstrap.Arguments)-1 {
			return false
		}
		for _, constant := range bootstrap.Arguments[1:] {
			if _, ok := bootstrapConstantString(constant); !ok {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func concatRecipeMarkerCounts(recipe string) (int, int) {
	var argMarkers, constMarkers int
	for _, marker := range recipe {
		switch marker {
		case '\u0001':
			argMarkers++
		case '\u0002':
			constMarkers++
		}
	}
	return argMarkers, constMarkers
}

func validLambdaMetafactoryLinkage(
	cf *classModel,
	dynamic invokeDynamicReference,
	bootstrap *bootstrapMethod,
	parsed methodDescriptor,
	summaries summarySet,
) (bool, error) {
	samShape, ok := supportedLambdaSAMShape(parsed.Return)
	if bootstrap == nil || !ok || dynamic.Name != samShape.Method {
		return false, nil
	}
	var target constantValue
	var samMethod, instantiatedMethod constantValue
	switch bootstrap.Handle.Name {
	case "metafactory":
		if len(bootstrap.Arguments) != 3 ||
			bootstrap.Arguments[0].Kind != constantMethodType ||
			bootstrap.Arguments[1].Kind != constantMethodHandle ||
			bootstrap.Arguments[2].Kind != constantMethodType {
			return false, nil
		}
		samMethod = bootstrap.Arguments[0]
		target = bootstrap.Arguments[1]
		instantiatedMethod = bootstrap.Arguments[2]
	case "altMetafactory":
		if len(bootstrap.Arguments) < 4 ||
			bootstrap.Arguments[0].Kind != constantMethodType ||
			bootstrap.Arguments[1].Kind != constantMethodHandle ||
			bootstrap.Arguments[2].Kind != constantMethodType ||
			bootstrap.Arguments[3].Kind != constantInteger {
			return false, nil
		}
		if bootstrap.Arguments[3].Integer != 0 || len(bootstrap.Arguments) != 4 {
			return false, nil
		}
		samMethod = bootstrap.Arguments[0]
		target = bootstrap.Arguments[1]
		instantiatedMethod = bootstrap.Arguments[2]
	default:
		return false, nil
	}
	if target.Reference == nil || target.HandleKind != 6 {
		return false, nil
	}
	if !lambdaImplementationTargetResolvesStatic(cf, *target.Reference, summaries) {
		return false, nil
	}
	if samMethod.String != samShape.Descriptor || instantiatedMethod.String != samShape.Descriptor {
		return false, nil
	}
	samDescriptor, err := parseMethodDescriptor(samMethod.String)
	if err != nil {
		return false, nil
	}
	instantiatedDescriptor, err := parseMethodDescriptor(instantiatedMethod.String)
	if err != nil {
		return false, nil
	}
	targetDescriptor, err := parseMethodDescriptor(target.Reference.Descriptor)
	if err != nil {
		return false, fmt.Errorf("lambda target descriptor: %w", err)
	}
	if len(samDescriptor.Parameters) != len(instantiatedDescriptor.Parameters) ||
		!descriptorTypesEqual(samDescriptor.Return, instantiatedDescriptor.Return) {
		return false, nil
	}
	if len(targetDescriptor.Parameters) != len(parsed.Parameters)+len(instantiatedDescriptor.Parameters) ||
		!descriptorTypesEqual(targetDescriptor.Return, instantiatedDescriptor.Return) {
		return false, nil
	}
	for index, parameter := range parsed.Parameters {
		if !descriptorTypesEqual(targetDescriptor.Parameters[index], parameter) {
			return false, nil
		}
	}
	for index, parameter := range instantiatedDescriptor.Parameters {
		if !descriptorTypesEqual(targetDescriptor.Parameters[len(parsed.Parameters)+index], parameter) {
			return false, nil
		}
	}
	return true, nil
}

func lambdaImplementationTargetResolvesStatic(cf *classModel, ref memberReference, summaries summarySet) bool {
	key := methodKey{Owner: ref.Owner, Name: ref.Name, Descriptor: ref.Descriptor}
	namespace := summaryLambdaClass
	if ref.Interface {
		namespace = summaryLambdaInterface
	}
	if _, ok := summaries[summaryKey{Method: key, Namespace: namespace}]; ok {
		return true
	}
	if cf == nil || ref.Owner != cf.Name {
		return false
	}
	if ref.Interface != (cf.Access&0x0200 != 0) {
		return false
	}
	for index := range cf.Methods {
		method := &cf.Methods[index]
		if method.Name != ref.Name || method.Descriptor != ref.Descriptor {
			continue
		}
		return method.Access&0x0008 != 0 && method.Code != nil
	}
	return false
}

type lambdaSAMShape struct {
	Method     string
	Descriptor string
}

func supportedLambdaSAMShape(returnType descriptorType) (lambdaSAMShape, bool) {
	if returnType.Void || returnType.Object == "" || returnType.Array {
		return lambdaSAMShape{}, false
	}
	shape, ok := supportedLambdaSAMShapes[returnType.Object]
	return shape, ok
}

var supportedLambdaSAMShapes = map[string]lambdaSAMShape{
	"java/lang/Runnable": {Method: "run", Descriptor: "()V"},
}

func descriptorTypesEqual(left, right descriptorType) bool {
	return left.Descriptor == right.Descriptor && left.Void == right.Void && left.Width == right.Width
}

func isStringConcatBootstrap(bootstrap *bootstrapMethod) bool {
	if bootstrap == nil || bootstrap.HandleKind != 6 || bootstrap.Handle.Owner != "java/lang/invoke/StringConcatFactory" {
		return false
	}
	switch bootstrap.Handle.Name {
	case "makeConcat":
		return bootstrap.Handle.Descriptor == "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
	case "makeConcatWithConstants":
		return bootstrap.Handle.Descriptor == "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"
	default:
		return false
	}
}

func isLambdaMetafactoryBootstrap(bootstrap *bootstrapMethod) bool {
	if bootstrap == nil || bootstrap.HandleKind != 6 || bootstrap.Handle.Owner != "java/lang/invoke/LambdaMetafactory" {
		return false
	}
	switch bootstrap.Handle.Name {
	case "metafactory":
		return bootstrap.Handle.Descriptor == "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodType;Ljava/lang/invoke/MethodHandle;Ljava/lang/invoke/MethodType;)Ljava/lang/invoke/CallSite;"
	case "altMetafactory":
		return bootstrap.Handle.Descriptor == "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;[Ljava/lang/Object;)Ljava/lang/invoke/CallSite;"
	default:
		return false
	}
}

func lambdaTarget(bootstrap *bootstrapMethod) (memberReference, bool) {
	if bootstrap == nil {
		return memberReference{}, false
	}
	for _, argument := range bootstrap.Arguments {
		if argument.Kind == constantMethodHandle && argument.Reference != nil {
			return *argument.Reference, true
		}
	}
	return memberReference{}, false
}

func concatConstants(values []abstractValue, limits Limits) (string, bool) {
	var builder strings.Builder
	for _, value := range values {
		if value.Constant == "" {
			return "", false
		}
		if builder.Len()+len(value.Constant) > limits.MaxConstantBytes {
			return "", false
		}
		builder.WriteString(value.Constant)
	}
	return builder.String(), true
}

func invokeDynamicConcatConstant(bootstrap *bootstrapMethod, args []abstractValue, limits Limits) (string, bool) {
	if bootstrap == nil {
		return "", false
	}
	switch bootstrap.Handle.Name {
	case "makeConcat":
		return concatConstants(args, limits)
	case "makeConcatWithConstants":
		if len(bootstrap.Arguments) == 0 || bootstrap.Arguments[0].Kind != constantString {
			return "", false
		}
		return concatRecipeConstant(bootstrap.Arguments[0].String, bootstrap.Arguments[1:], args, limits)
	default:
		return "", false
	}
}

func concatRecipeConstant(recipe string, constants []constantValue, args []abstractValue, limits Limits) (string, bool) {
	var builder strings.Builder
	argIndex, constantIndex := 0, 0
	appendText := func(value string) bool {
		if builder.Len()+len(value) > limits.MaxConstantBytes {
			return false
		}
		builder.WriteString(value)
		return true
	}
	for _, marker := range recipe {
		switch marker {
		case '\u0001':
			if argIndex >= len(args) || args[argIndex].Constant == "" || !appendText(args[argIndex].Constant) {
				return "", false
			}
			argIndex++
		case '\u0002':
			if constantIndex >= len(constants) {
				return "", false
			}
			value, ok := bootstrapConstantString(constants[constantIndex])
			if !ok || !appendText(value) {
				return "", false
			}
			constantIndex++
		default:
			if !appendText(string(marker)) {
				return "", false
			}
		}
	}
	if argIndex != len(args) {
		return "", false
	}
	return builder.String(), true
}

func bootstrapConstantString(value constantValue) (string, bool) {
	switch value.Kind {
	case constantString, constantClass, constantMethodType:
		return value.String, value.String != ""
	case constantInteger, constantLong:
		return strconv.FormatInt(value.Integer, 10), true
	case constantFloat, constantDouble:
		return strconv.FormatInt(value.Integer, 10), true
	default:
		return "", false
	}
}

func decodeConstantTransform(ref memberReference, value string, limits Limits) (string, bool) {
	if value == "" {
		return "", false
	}
	var decoded []byte
	var err error
	switch {
	case base64DecodeAPIs.matches(ref):
		for _, encoding := range []*base64.Encoding{
			base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
		} {
			decoded, err = encoding.DecodeString(value)
			if err == nil {
				break
			}
		}
		if err != nil {
			return "", false
		}
	case hexDecodeAPIs.matches(ref):
		decoded, err = hex.DecodeString(value)
		if err != nil {
			return "", false
		}
	case urlDecodeAPIs.matches(ref):
		text, textErr := url.QueryUnescape(value)
		if textErr != nil {
			text, textErr = url.PathUnescape(value)
		}
		if textErr != nil || len(text) > limits.MaxConstantBytes {
			return "", false
		}
		return text, true
	default:
		return "", false
	}
	if int64(len(decoded)) > limits.MaxDecodedBytes || len(decoded) > limits.MaxConstantBytes {
		return "", false
	}
	return string(decoded), true
}

func modelConstructorHeap(
	ref memberReference,
	receiver abstractValue,
	args []abstractValue,
	f *frame,
	limits Limits,
	budget *abstractBudget,
) error {
	value, err := resolveWrittenValue(args, f, limits, budget)
	if err != nil {
		return err
	}
	for i := 0; i < identityCount(receiver); i++ {
		id := identityAt(receiver, i)
		object := cloneHeapObject(f.Heap[id])
		switch ref.Owner {
		case "java/lang/String", "java/lang/StringBuilder", "java/lang/StringBuffer":
			object.Builder, err = mergeSemanticValues(object.Builder, value, limits, budget)
		case "java/io/FileOutputStream", "java/io/FileWriter":
			object.Builder, err = mergeSemanticValues(object.Builder, firstArg(args), limits, budget)
		default:
			object.Stream, err = mergeSemanticValues(object.Stream, value, limits, budget)
		}
		if err != nil {
			return err
		}
		if err := setHeapObject(f, id, object, limits, budget); err != nil {
			return err
		}
	}
	return nil
}

func mergeHeapSlot(
	receiver abstractValue,
	f *frame,
	limits Limits,
	budget *abstractBudget,
	assign func(*heapObject, abstractValue),
	incoming heapObject,
) error {
	for i := 0; i < identityCount(receiver); i++ {
		id := identityAt(receiver, i)
		object := cloneHeapObject(f.Heap[id])
		var merged abstractValue
		var err error
		switch {
		case incoming.Builder.Width != 0:
			merged, err = mergeSemanticValues(object.Builder, incoming.Builder, limits, budget)
		case incoming.Stream.Width != 0:
			merged, err = mergeSemanticValues(object.Stream, incoming.Stream, limits, budget)
		default:
			merged = abstractValue{}
		}
		if err != nil {
			return err
		}
		assign(&object, merged)
		if err := setHeapObject(f, id, object, limits, budget); err != nil {
			return err
		}
	}
	return nil
}

func propagateStreamWriteToDelegates(
	receiver abstractValue,
	written abstractValue,
	f *frame,
	limits Limits,
	budget *abstractBudget,
) error {
	targets := make(map[uint32]struct{})
	for i := 0; i < identityCount(receiver); i++ {
		receiverID := identityAt(receiver, i)
		object, ok := f.Heap[receiverID]
		if !ok {
			continue
		}
		for j := 0; j < identityCount(object.Stream); j++ {
			target := identityAt(object.Stream, j)
			if target == 0 || target == receiverID {
				continue
			}
			targets[target] = struct{}{}
		}
	}
	if len(targets) == 0 {
		return nil
	}
	ids := make([]uint32, 0, len(targets))
	for id := range targets {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	if len(ids) > limits.MaxCallTargets {
		ids = ids[:limits.MaxCallTargets]
	}
	for _, id := range ids {
		object := cloneHeapObject(f.Heap[id])
		var err error
		object.Stream, err = mergeSemanticValues(object.Stream, written, limits, budget)
		if err != nil {
			return err
		}
		if err := setHeapObject(f, id, object, limits, budget); err != nil {
			return err
		}
	}
	return nil
}

func resultFromHeap(
	base abstractValue,
	receiver abstractValue,
	f *frame,
	limits Limits,
	budget *abstractBudget,
	step provenanceStep,
	selectValues func(heapObject) []abstractValue,
) (abstractValue, bool, error) {
	values, found, err := selectedHeapValues(receiver, f, limits, budget, selectValues)
	if err != nil || !found {
		return abstractValue{}, found, err
	}
	result, err := deriveModeledResult(base, []abstractValue{values}, step, limits, budget)
	return result, true, err
}

func selectedHeapValues(
	receiver abstractValue,
	f *frame,
	limits Limits,
	budget *abstractBudget,
	selectValues func(heapObject) []abstractValue,
) (abstractValue, bool, error) {
	var result abstractValue
	found := false
	for i := 0; i < identityCount(receiver); i++ {
		object, ok := f.Heap[identityAt(receiver, i)]
		if !ok {
			continue
		}
		for _, value := range selectValues(object) {
			if value.Width == 0 {
				continue
			}
			var err error
			result, err = mergeSemanticValues(result, value, limits, budget)
			if err != nil {
				return abstractValue{}, false, err
			}
			found = true
		}
	}
	return result, found, nil
}

func resolveWrittenValue(args []abstractValue, f *frame, limits Limits, budget *abstractBudget) (abstractValue, error) {
	var result abstractValue
	for _, arg := range args {
		value, err := resolveCommandValue(arg, f, limits, budget)
		if err != nil {
			return abstractValue{}, err
		}
		result, err = mergeSemanticValues(result, value, limits, budget)
		if err != nil {
			return abstractValue{}, err
		}
	}
	return result, nil
}

func hookRegistrationCodeValue(ref memberReference, args []abstractValue, f *frame, limits Limits, budget *abstractBudget) (abstractValue, error) {
	indexes := hookCodeArgumentIndexes(ref)
	if len(indexes) == 0 {
		return abstractValue{}, nil
	}
	var result abstractValue
	for _, index := range indexes {
		if index < 0 || index >= len(args) {
			continue
		}
		value, err := resolveCommandValue(args[index], f, limits, budget)
		if err != nil {
			return abstractValue{}, err
		}
		result, err = mergeSemanticValues(result, value, limits, budget)
		if err != nil {
			return abstractValue{}, err
		}
	}
	return result, nil
}

func hookCodeArgumentIndexes(ref memberReference) []int {
	switch ref.Owner {
	case "javax/servlet/ServletContext", "jakarta/servlet/ServletContext":
		switch ref.Name {
		case "addServlet", "addFilter":
			return []int{1}
		case "addListener":
			return []int{0}
		case "addJspFile":
			return []int{1}
		}
	case "javax/servlet/ServletRegistration$Dynamic", "jakarta/servlet/ServletRegistration$Dynamic",
		"javax/servlet/FilterRegistration$Dynamic", "jakarta/servlet/FilterRegistration$Dynamic":
		return nil
	case "javax/websocket/server/ServerContainer", "jakarta/websocket/server/ServerContainer":
		return []int{0}
	case "org/apache/catalina/core/StandardContext":
		switch ref.Name {
		case "addFilterDef", "addApplicationEventListener", "addApplicationLifecycleListener", "addChild":
			return []int{0}
		case "addServletMappingDecoded", "addFilterMap", "addFilterMapBefore":
			return nil
		}
	case "org/apache/catalina/Context":
		if ref.Name == "addApplicationEventListener" {
			return []int{0}
		}
		return nil
	case "org/apache/catalina/Pipeline", "org/apache/catalina/core/StandardPipeline":
		if ref.Name == "addValve" {
			return []int{0}
		}
	case "org/springframework/web/servlet/mvc/method/annotation/RequestMappingHandlerMapping",
		"org/springframework/web/reactive/result/method/annotation/RequestMappingHandlerMapping",
		"org/springframework/web/servlet/handler/AbstractHandlerMethodMapping",
		"org/springframework/web/reactive/result/method/AbstractHandlerMethodMapping":
		if ref.Name == "registerMapping" {
			return []int{1, 2}
		}
	case "org/springframework/web/servlet/handler/AbstractUrlHandlerMapping":
		if ref.Name == "registerHandler" {
			return []int{1}
		}
	case "org/springframework/web/servlet/config/annotation/InterceptorRegistry":
		if ref.Name == "addInterceptor" {
			return []int{0}
		}
	case "org/springframework/web/servlet/handler/AbstractHandlerMapping":
		if ref.Name == "setInterceptors" {
			return []int{0}
		}
	}
	return nil
}

func modelCollectionMutation(
	ref memberReference,
	receiver abstractValue,
	args []abstractValue,
	f *frame,
	limits Limits,
	budget *abstractBudget,
) error {
	for i := 0; i < identityCount(receiver); i++ {
		id := identityAt(receiver, i)
		object := cloneHeapObject(f.Heap[id])
		switch ref.Owner {
		case "java/util/List":
			value := firstArg(args)
			if len(args) > 1 {
				value = args[len(args)-1]
			}
			if len(object.List) < limits.MaxCallTargets {
				object.List = append(object.List, cloneValue(value))
			} else if len(object.List) != 0 {
				merged, err := mergeSemanticValues(object.List[len(object.List)-1], value, limits, budget)
				if err != nil {
					return err
				}
				object.List[len(object.List)-1] = merged
			}
		case "java/util/Map":
			if len(args) < 2 {
				continue
			}
			entry := heapEntry{Key: args[0].Constant, KeyKnown: args[0].Constant != "", Value: cloneValue(args[1])}
			index := -1
			for j := range object.Map {
				if object.Map[j].Key == entry.Key && object.Map[j].KeyKnown == entry.KeyKnown {
					index = j
					break
				}
			}
			if index >= 0 {
				merged, err := mergeSemanticValues(object.Map[index].Value, entry.Value, limits, budget)
				if err != nil {
					return err
				}
				object.Map[index].Value = merged
			} else if len(object.Map) < limits.MaxCallTargets {
				object.Map = append(object.Map, entry)
			}
			sort.Slice(object.Map, func(i, j int) bool {
				if object.Map[i].KeyKnown != object.Map[j].KeyKnown {
					return !object.Map[i].KeyKnown
				}
				return object.Map[i].Key < object.Map[j].Key
			})
		}
		if err := setHeapObject(f, id, object, limits, budget); err != nil {
			return err
		}
	}
	return nil
}

func collectionReadValue(
	ref memberReference,
	receiver abstractValue,
	args []abstractValue,
	f *frame,
	limits Limits,
	budget *abstractBudget,
) (abstractValue, bool, error) {
	return selectedHeapValues(receiver, f, limits, budget, func(object heapObject) []abstractValue {
		if ref.Owner == "java/util/List" {
			if len(object.List) == 0 {
				return nil
			}
			if len(args) != 0 {
				if index, ok := exactIntegerConstant(args[0]); ok && index >= 0 && index < int64(len(object.List)) {
					return []abstractValue{object.List[index]}
				}
			}
			return object.List
		}
		if len(args) == 0 {
			return nil
		}
		key := args[0].Constant
		keyKnown := key != ""
		values := make([]abstractValue, 0, len(object.Map))
		for _, entry := range object.Map {
			if !keyKnown || !entry.KeyKnown || entry.Key == key {
				values = append(values, entry.Value)
			}
		}
		return values
	})
}

func processBuilderCommand(
	receiver abstractValue,
	f *frame,
	limits Limits,
	budget *abstractBudget,
) (abstractValue, bool, error) {
	var command abstractValue
	found := false
	for i := 0; i < identityCount(receiver); i++ {
		candidate, ok := f.Fields[processBuilderCommandKey(identityAt(receiver, i))]
		if !ok {
			continue
		}
		var err error
		command, err = mergeSemanticValues(command, candidate, limits, budget)
		if err != nil {
			return abstractValue{}, false, err
		}
		found = true
	}
	if found {
		resolved, err := resolveCommandValue(command, f, limits, budget)
		if err != nil {
			return abstractValue{}, false, err
		}
		command = resolved
	}
	return command, found, nil
}

func classloadPayload(args []abstractValue, f *frame, limits Limits, budget *abstractBudget) (abstractValue, bool, error) {
	for _, arg := range args {
		if arg.Reference == "[B" || arg.Kinds&(kindBytes|kindClassBytes) != 0 {
			resolved, err := resolveCommandValue(arg, f, limits, budget)
			return resolved, true, err
		}
	}
	if len(args) == 0 {
		return abstractValue{}, false, nil
	}
	resolved, err := resolveCommandValue(args[0], f, limits, budget)
	return resolved, true, err
}

func modelExecutableWrite(
	ref memberReference,
	args []abstractValue,
	ins instruction,
	f *frame,
	analysis *methodAnalysis,
	opts Options,
	budget *abstractBudget,
) error {
	if ref.Name == "newOutputStream" && len(args) != 0 {
		return nil
	}
	if len(args) < 2 {
		return nil
	}
	path, err := resolveCommandValue(args[0], f, opts.Limits, budget)
	if err != nil {
		return err
	}
	content, err := resolveCommandValue(args[1], f, opts.Limits, budget)
	if err != nil {
		return err
	}
	if !dangerousExecutableDestination(path.Constant, opts) || !executionInput(content, analysis) {
		return nil
	}
	return recordSink(analysis, sinkExecutableWrite, 85, content, ins.Offset, shortAPI(ref), opts.Limits, budget)
}

func exactPathTransformConstant(args []abstractValue, f *frame, limits Limits, budget *abstractBudget) (string, bool, error) {
	if len(args) == 0 || args[0].Constant == "" {
		return "", false, nil
	}
	components := []string{args[0].Constant}
	if len(args) > 1 {
		rest, ok, err := exactStringArrayConstants(args[1], f, limits, budget)
		if err != nil || !ok {
			return "", false, err
		}
		components = append(components, rest...)
	}
	clean := filepath.Clean(filepath.Join(components...))
	if len(clean) > limits.MaxConstantBytes {
		return "", false, nil
	}
	return clean, true, nil
}

func exactStringArrayConstants(array abstractValue, f *frame, limits Limits, budget *abstractBudget) ([]string, bool, error) {
	if !array.LengthKnown || array.ArrayLength < 0 || array.ArrayLength > int64(limits.MaxCallTargets) || identityCount(array) != 1 {
		return nil, false, nil
	}
	id := identityAt(array, 0)
	if _, ok := f.Fields[arrayElementKey(id)]; ok {
		return nil, false, nil
	}
	result := make([]string, int(array.ArrayLength))
	for index := range result {
		key := arrayIndexedElementKey(id, int64(index))
		value, ok := f.Fields[key]
		if !ok {
			return nil, false, nil
		}
		resolved, err := resolveCommandValue(value, f, limits, budget)
		if err != nil {
			return nil, false, err
		}
		if resolved.Constant == "" {
			return nil, false, nil
		}
		result[index] = resolved.Constant
	}
	return result, true, nil
}

func receiverExecutablePath(
	receiver abstractValue,
	f *frame,
	opts Options,
	budget *abstractBudget,
) (string, bool, error) {
	path, found, err := selectedHeapValues(receiver, f, opts.Limits, budget, func(object heapObject) []abstractValue {
		return []abstractValue{object.Builder}
	})
	if err != nil || !found || path.Constant == "" {
		return "", false, err
	}
	return path.Constant, true, nil
}

func dangerousExecutableDestination(value string, opts Options) bool {
	if value == "" {
		return false
	}
	clean := filepath.Clean(value)
	slashed := filepath.ToSlash(clean)
	lower := strings.ToLower(slashed)
	switch strings.ToLower(filepath.Ext(clean)) {
	case ".jsp", ".jspx", ".class", ".jar":
		return true
	}
	if strings.Contains(lower, "/web-inf/classes/") || strings.HasSuffix(lower, "/web-inf/classes") ||
		strings.Contains(lower, "/web-inf/lib/") || strings.HasSuffix(lower, "/web-inf/lib") {
		return true
	}
	for _, root := range opts.Webroots {
		if root == "" {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(root), clean)
		if err == nil && rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel) {
			return true
		}
	}
	return false
}

func resolveCommandValue(value abstractValue, f *frame, limits Limits, budget *abstractBudget) (abstractValue, error) {
	if err := budget.chargeValueCopies("command value resolution", 0, []abstractValue{value}, 1); err != nil {
		return abstractValue{}, err
	}
	result := cloneValue(value)
	if identityCount(value) == 0 {
		return result, nil
	}
	keys, err := orderedFieldKeysBudget(f.Fields, budget, "command array field scan")
	if err != nil {
		return abstractValue{}, err
	}
	for i := 0; i < identityCount(value); i++ {
		id := identityAt(value, i)
		if object, ok := f.Heap[id]; ok {
			for _, heapValue := range heapSemanticValues(object) {
				if heapValue.Width == 0 {
					continue
				}
				result, err = mergeSemanticValues(result, heapValue, limits, budget)
				if err != nil {
					return abstractValue{}, err
				}
			}
		}
		for _, key := range keys {
			if !isArrayElementKey(key, id) {
				continue
			}
			if element, ok := f.Fields[key]; ok {
				result, err = mergeSemanticValues(result, element, limits, budget)
				if err != nil {
					return abstractValue{}, err
				}
			}
		}
	}
	return result, nil
}

func heapSemanticValues(object heapObject) []abstractValue {
	values := make([]abstractValue, 0, 2+len(object.List)+len(object.Map))
	values = append(values, object.Builder, object.Stream)
	values = append(values, object.List...)
	for _, entry := range object.Map {
		values = append(values, entry.Value)
	}
	return values
}

func validateInvokeLegality(cf *classModel, opcode byte, ref memberReference, name, descriptor string) error {
	if name == "<clinit>" {
		return fmt.Errorf("<clinit> cannot be invoked explicitly")
	}
	if name == "<init>" {
		if opcode != 0xb7 {
			return fmt.Errorf("<init> requires invokespecial")
		}
		parsed, err := parseMethodDescriptor(descriptor)
		if err != nil {
			return err
		}
		if !parsed.Return.Void {
			return fmt.Errorf("<init> must return void")
		}
		return nil
	}
	if strings.HasPrefix(name, "<") {
		return fmt.Errorf("invalid special method name %q", name)
	}
	if opcode == 0xb7 && !provableInvokeSpecialOwner(cf, ref.Owner) {
		return fmt.Errorf("invokespecial owner %s is not current class, direct superclass, or direct interface", ref.Owner)
	}
	if access, ok := currentMethodAccess(cf, ref); ok {
		static := access&0x0008 != 0
		if opcode == 0xb8 && !static {
			return fmt.Errorf("instance method %s.%s cannot be invoked statically", ref.Owner, ref.Name)
		}
		if opcode != 0xb8 && static {
			return fmt.Errorf("static method %s.%s requires invokestatic", ref.Owner, ref.Name)
		}
	}
	if expected := modeledInvokeOpcode(ref); expected != 0 && opcode != expected {
		return fmt.Errorf("modeled API %s.%s requires opcode 0x%02x", ref.Owner, ref.Name, expected)
	}
	if opcode == 0xb9 && knownConcreteReferenceType(ref.Owner) {
		return fmt.Errorf("invokeinterface owner %s is a known class", ref.Owner)
	}
	return nil
}

func provableInvokeSpecialOwner(cf *classModel, owner string) bool {
	if cf == nil || owner == "" {
		return false
	}
	if owner == cf.Name || owner == cf.Super {
		return true
	}
	for _, candidate := range cf.Interfaces {
		if owner == candidate {
			return true
		}
	}
	return false
}

func currentMethodAccess(cf *classModel, ref memberReference) (uint16, bool) {
	if cf == nil || ref.Owner != cf.Name {
		return 0, false
	}
	for _, method := range cf.Methods {
		if method.Name == ref.Name && method.Descriptor == ref.Descriptor {
			return method.Access, true
		}
	}
	return 0, false
}

func modeledInvokeOpcode(ref memberReference) byte {
	switch {
	case modeledStaticAPI(ref):
		return 0xb8
	case modeledInterfaceAPI(ref):
		return 0xb9
	case runtimeExecAPIs.matches(ref), processBuilderStartAPIs.matches(ref), pageContextRequestAPIs.matches(ref),
		modeledVirtualAPI(ref):
		return 0xb6
	case processBuilderConstructorAPIs.matches(ref):
		return 0xb7
	case requestSourceAPIs.matches(ref), sessionAttributeSourceAPIs.matches(ref), applicationAttributeSourceAPIs.matches(ref):
		return 0xb9
	case ref.Owner == "java/lang/Runtime" && ref.Name == "getRuntime" && ref.Descriptor == "()Ljava/lang/Runtime;":
		return 0xb8
	default:
		return 0
	}
}

func modeledStaticAPI(ref memberReference) bool {
	if ref.Owner == "java/lang/Runtime" && ref.Name == "getRuntime" && ref.Descriptor == "()Ljava/lang/Runtime;" {
		return true
	}
	if executableWriteAPIs.matches(ref) || pathTransformAPIs.matches(ref) || urlDecodeAPIs.matches(ref) ||
		hexDecodeAPIs.matches(ref) {
		return true
	}
	if base64DecodeAPIs.matches(ref) && ref.Owner != "java/util/Base64$Decoder" {
		return true
	}
	if ref.Owner == "java/lang/String" && (ref.Name == "valueOf" || ref.Name == "copyValueOf") && stringTransformAPIs.matches(ref) {
		return true
	}
	if (ref.Owner == "groovy/util/Eval" || ref.Owner == "ognl/Ognl" ||
		ref.Owner == "org/mvel2/MVEL" || ref.Owner == "org/mvel/MVEL") && scriptEvaluationAPIs.matches(ref) {
		return true
	}
	return false
}

func modeledInterfaceAPI(ref memberReference) bool {
	switch ref.Owner {
	case "javax/servlet/http/HttpServletRequest", "jakarta/servlet/http/HttpServletRequest",
		"javax/servlet/ServletRequest", "jakarta/servlet/ServletRequest",
		"javax/servlet/ServletResponse", "jakarta/servlet/ServletResponse",
		"javax/servlet/http/HttpServletResponse", "jakarta/servlet/http/HttpServletResponse",
		"javax/servlet/ServletContext", "jakarta/servlet/ServletContext",
		"javax/servlet/ServletRegistration$Dynamic", "jakarta/servlet/ServletRegistration$Dynamic",
		"javax/servlet/FilterRegistration$Dynamic", "jakarta/servlet/FilterRegistration$Dynamic",
		"javax/websocket/server/ServerContainer", "jakarta/websocket/server/ServerContainer",
		"javax/script/ScriptEngine", "javax/script/Compilable",
		"javax/naming/Context", "javax/naming/directory/DirContext",
		"java/util/List", "java/util/Map":
		return requestSourceAPIs.matches(ref) || responseAccessAPIs.matches(ref) || hookRegistrationAPIs.matches(ref) ||
			scriptEvaluationAPIs.matches(ref) || jndiLookupAPIs.matches(ref) || isCollectionMutation(ref) || isCollectionRead(ref)
	default:
		return false
	}
}

func modeledVirtualAPI(ref memberReference) bool {
	if stringTransformAPIs.matches(ref) && (ref.Name == "concat" || ref.Name == "getBytes") {
		return true
	}
	if base64DecodeAPIs.matches(ref) || isBuilderAppend(ref) || isBuilderResult(ref) || isStreamWrite(ref) ||
		isStreamResult(ref) || isCompressionTransform(ref) || classDefinitionAPIs.matches(ref) ||
		scriptEvaluationAPIs.matches(ref) || reflectionExecutionAPIs.matches(ref) || deserializationAPIs.matches(ref) ||
		jndiLookupAPIs.matches(ref) || hookRegistrationAPIs.matches(ref) || responseAccessAPIs.matches(ref) {
		return true
	}
	return false
}

func knownConcreteReferenceType(name string) bool {
	_, ok := knownClosedReferenceTypes[name]
	return ok || name == "java/lang/Object" || name == "java/lang/Process"
}

type receiverShapeStatus uint8

const (
	receiverShapeTrusted receiverShapeStatus = iota
	receiverShapeUnproven
	receiverShapeInvalid
)

func modeledReceiverShapeStatus(cf *classModel, receiver abstractValue, ref memberReference) receiverShapeStatus {
	if ref.Owner == "" || isKnownNull(receiver) {
		return receiverShapeTrusted
	}
	source := receiver.Reference
	if runtimeType := exactRuntimeType(receiver); runtimeType != "" {
		source = runtimeType
	}
	if source == "" {
		return receiverShapeUnproven
	}
	if explicitReferenceAssignableTo(cf, source, ref.Owner) {
		return receiverShapeTrusted
	}
	if positivelyInvalidModeledReceiver(cf, source, ref.Owner) {
		return receiverShapeInvalid
	}
	return receiverShapeUnproven
}

func positivelyInvalidModeledReceiver(cf *classModel, source, target string) bool {
	if source == "" {
		return false
	}
	if strings.HasPrefix(source, "[") || strings.HasPrefix(target, "[") {
		return true
	}
	if knownConcreteReferenceType(source) {
		return true
	}
	if cf != nil && source == cf.Name && cf.Super == "java/lang/Object" {
		return true
	}
	_, sourceKnown := knownReferenceSupers[source]
	_, targetKnown := knownReferenceSupers[target]
	return sourceKnown && targetKnown
}

func explicitReferenceAssignableTo(cf *classModel, source, target string) bool {
	if source == "" {
		return false
	}
	if source == target || target == "java/lang/Object" {
		return true
	}
	if strings.HasPrefix(source, "[") {
		return explicitArrayAssignableTo(source, target)
	}
	if strings.HasPrefix(target, "[") {
		return false
	}
	if cf != nil && source == cf.Name {
		if cf.Super == target {
			return true
		}
		for _, name := range cf.Interfaces {
			if name == target {
				return true
			}
		}
	}
	return knownReferenceReachable(source, target)
}

func explicitArrayAssignableTo(source, target string) bool {
	if source == target || target == "java/lang/Object" || target == "java/lang/Cloneable" || target == "java/io/Serializable" {
		return true
	}
	if !strings.HasPrefix(target, "[") || source == "[" || target == "[" {
		return false
	}
	if _, err := parseFieldDescriptor(source); err != nil {
		return false
	}
	if _, err := parseFieldDescriptor(target); err != nil {
		return false
	}
	sourceComponent, targetComponent := source[1:], target[1:]
	if sourceComponent == targetComponent {
		return true
	}
	if strings.HasPrefix(sourceComponent, "L") && strings.HasPrefix(targetComponent, "L") &&
		strings.HasSuffix(sourceComponent, ";") && strings.HasSuffix(targetComponent, ";") {
		return explicitReferenceAssignableTo(nil, sourceComponent[1:len(sourceComponent)-1], targetComponent[1:len(targetComponent)-1])
	}
	if strings.HasPrefix(sourceComponent, "[") && strings.HasPrefix(targetComponent, "[") {
		return explicitArrayAssignableTo(sourceComponent, targetComponent)
	}
	return false
}

func constructorReceiverMatches(cf *classModel, receiver abstractValue, owner string) bool {
	if receiver.ObjectID != receiverObjectID {
		return receiver.Reference == owner
	}
	return cf != nil && (owner == cf.Name || owner == cf.Super)
}

func invokesUninitializedThis(cf *classModel, ins instruction, f frame) bool {
	if ins.Opcode != 0xb7 {
		return false
	}
	ref, err := resolveInvokeOperand(cf, ins)
	if err != nil || ref.Name != "<init>" {
		return false
	}
	descriptor, err := parseMethodDescriptor(ref.Descriptor)
	if err != nil || len(f.Stack) <= len(descriptor.Parameters) {
		return false
	}
	receiver := f.Stack[len(f.Stack)-len(descriptor.Parameters)-1]
	return receiver.Verifier == verifierUninitialized && receiver.ObjectID == receiverObjectID
}

func poisonUninitializedThisAliases(f *frame) {
	poison := func(value *abstractValue) {
		if value.Verifier == verifierUninitialized && value.ObjectID == receiverObjectID {
			*value = abstractValue{}
		}
	}
	for index := range f.Locals {
		poison(&f.Locals[index])
	}
	for index := range f.Stack {
		poison(&f.Stack[index])
	}
}

func initializeAllocationAliases(f *frame, receiver abstractValue, budget *abstractBudget) error {
	if receiver.ObjectID == 0 || len(receiver.ObjectIDs) != 0 {
		return fmt.Errorf("constructor receiver must identify one allocation site")
	}
	if err := budget.charge("constructor alias initialization", len(f.Locals)+len(f.Stack)); err != nil {
		return err
	}
	initialize := func(value *abstractValue) {
		if value.Verifier == verifierUninitialized && value.ObjectID == receiver.ObjectID {
			value.Verifier = verifierReference
		}
	}
	for index := range f.Locals {
		initialize(&f.Locals[index])
	}
	for index := range f.Stack {
		initialize(&f.Stack[index])
	}
	return nil
}

func modeledInstanceAPI(ref memberReference) bool {
	return requestSourceAPIs.matches(ref) || pageContextRequestAPIs.matches(ref) ||
		sessionAttributeSourceAPIs.matches(ref) || applicationAttributeSourceAPIs.matches(ref) ||
		runtimeExecAPIs.matches(ref) || processBuilderConstructorAPIs.matches(ref) ||
		processBuilderStartAPIs.matches(ref)
}

func trustedInvocation(cf *classModel, ref memberReference) bool {
	if modeledInstanceAPI(ref) {
		return true
	}
	if ref.Owner == "java/lang/Runtime" && ref.Name == "getRuntime" && ref.Descriptor == "()Ljava/lang/Runtime;" {
		return true
	}
	if isModeledTransform(ref) || isModeledSink(cf, ref) || responseAccessAPIs.matches(ref) {
		return true
	}
	return ref.Owner == "java/lang/Object" && ref.Name == "<init>" && ref.Descriptor == "()V"
}

func requestSourceTaint(ref memberReference) taint {
	switch ref.Name {
	case "getParameter", "getParameterMap", "getParameterValues":
		return taintRequestParameter
	case "getHeader", "getHeaders":
		return taintRequestHeader
	case "getCookies":
		return taintCookie
	default:
		return taintRequestBody
	}
}

func processBuilderCommandKey(id uint32) fieldKey {
	return fieldKey{ObjectID: id, Owner: "java/lang/ProcessBuilder", Name: "<command>", Descriptor: "*"}
}

func setFrameField(f *frame, key fieldKey, value abstractValue, limits Limits, budget *abstractBudget) error {
	_, exists := f.Fields[key]
	if !exists && len(f.Locals)+stackSlots(f.Stack)+len(f.Fields)+heapSlots(f.Heap)+1 > limits.MaxFrameSlots {
		return &abstractBudgetError{detail: fmt.Sprintf(
			"frame field/object state exceeds slot limit %d before adding %s.%s",
			limits.MaxFrameSlots, key.Owner, key.Name,
		)}
	}
	if err := budget.charge("field/object state retention", 1+valueStateUnits(value)); err != nil {
		return err
	}
	f.Fields[key] = cloneValue(value)
	return nil
}

func setHeapObject(f *frame, id uint32, object heapObject, limits Limits, budget *abstractBudget) error {
	if id == 0 {
		return nil
	}
	if heapObjectStateUnits(object) > limits.MaxFrameSlots {
		return &abstractBudgetError{detail: fmt.Sprintf("heap object state exceeds slot limit %d", limits.MaxFrameSlots)}
	}
	prospectiveHeapSlots := heapSlots(f.Heap)
	if existing, exists := f.Heap[id]; exists {
		prospectiveHeapSlots -= 1 + heapObjectStateUnits(existing)
	}
	prospectiveHeapSlots += 1 + heapObjectStateUnits(object)
	if len(f.Locals)+stackSlots(f.Stack)+len(f.Fields)+prospectiveHeapSlots > limits.MaxFrameSlots {
		return &abstractBudgetError{detail: fmt.Sprintf("frame heap state exceeds slot limit %d", limits.MaxFrameSlots)}
	}
	if err := budget.charge("heap object retention", 1+heapObjectStateUnits(object)); err != nil {
		return err
	}
	if f.Heap == nil {
		f.Heap = make(map[uint32]heapObject)
	}
	f.Heap[id] = cloneHeapObject(object)
	return nil
}

func recordExecution(
	analysis *methodAnalysis,
	command abstractValue,
	offset uint32,
	api string,
	limits Limits,
	budget *abstractBudget,
) error {
	return recordSink(analysis, sinkExec, 85, command, offset, api, limits, budget)
}

func recordSink(
	analysis *methodAnalysis,
	kind sinkKind,
	score int,
	value abstractValue,
	offset uint32,
	api string,
	limits Limits,
	budget *abstractBudget,
) error {
	if score == 85 && value.SummaryOnly {
		score = 75
	}
	if analysis.summarizing && score >= 75 {
		analysis.Summary.SinkFromArgs[kind] = analysis.Summary.SinkFromArgs[kind].union(value.Arguments)
		analysis.Summary.SinkTaint[kind] |= value.Taint
	}
	if err := budget.chargeValueCopies("execution evidence provenance", 1, []abstractValue{{Provenance: value.Provenance}}, 1); err != nil {
		return err
	}
	sink := provenanceStep{Offset: offset, API: api}
	steps := appendProvenance(value.Provenance, sink, limits.MaxProvenanceSteps)
	source := provenanceStep{API: "request/session/application input"}
	if score <= 60 && !isExecutionTainted(value.Taint) {
		source = provenanceStep{API: "constant/resolved runtime mutation"}
	}
	for _, step := range value.Provenance {
		if step.API != "" {
			source = step
			break
		}
	}
	result := sinkResult{Kind: kind, Score: score, Evidence: steps, Source: source, Sink: sink}
	replace := -1
	for index, existing := range analysis.SinkResults {
		if existing.Kind != kind {
			continue
		}
		if score > existing.Score || score == existing.Score && provenanceLess(steps, existing.Evidence) {
			replace = index
		} else {
			return nil
		}
		break
	}
	if replace >= 0 {
		analysis.SinkResults[replace] = result
	} else {
		analysis.SinkResults = append(analysis.SinkResults, result)
	}
	sort.Slice(analysis.SinkResults, func(i, j int) bool { return analysis.SinkResults[i].Kind < analysis.SinkResults[j].Kind })
	if kind == sinkExec && (!analysis.RequestExec || provenanceLess(steps, analysis.Evidence)) {
		analysis.RequestExec = true
		analysis.Evidence = steps
		analysis.Source = source
		analysis.Sink = sink
	}
	return nil
}

func transferWide(ins instruction, f *frame, push func(abstractValue) error, budget *abstractBudget) error {
	if len(ins.Operands) != 3 && len(ins.Operands) != 5 {
		return fmt.Errorf("invalid wide operands")
	}
	op := ins.Operands[0]
	index := int(binary.BigEndian.Uint16(ins.Operands[1:3]))
	switch {
	case op >= 0x15 && op <= 0x19:
		return loadLocal(f, index, loadStoreWidth(op), loadStoreVerifier(op), push)
	case op >= 0x36 && op <= 0x3a:
		value, err := popValue(f, loadStoreWidth(op))
		if err != nil {
			return err
		}
		if !valueMatchesLoadStore(op, value) {
			return fmt.Errorf("wide store opcode requires compatible verifier type")
		}
		return storeLocal(f, index, value, budget)
	case op == 0x84:
		return validateIINC(f, index)
	case op == 0xa9:
		return fmt.Errorf("reachable jsr/ret is unsupported")
	default:
		return fmt.Errorf("unsupported wide transfer")
	}
}

func resolveInvokeOperand(cf *classModel, ins instruction) (memberReference, error) {
	if len(ins.Operands) < 2 {
		return memberReference{}, fmt.Errorf("truncated invoke operand")
	}
	index := binary.BigEndian.Uint16(ins.Operands[:2])
	entry, err := cf.poolEntry(index)
	if err != nil {
		return memberReference{}, err
	}
	valid := false
	switch ins.Opcode {
	case 0xb6:
		valid = entry.tag == cpMethodref
	case 0xb7, 0xb8:
		valid = entry.tag == cpMethodref || cf.Major >= 52 && entry.tag == cpInterfaceMethodref
	case 0xb9:
		valid = entry.tag == cpInterfaceMethodref
	}
	if !valid {
		return memberReference{}, fmt.Errorf("constant-pool tag %d is invalid for invoke opcode", entry.tag)
	}
	return cf.memberRef(index)
}

func resolveFieldOperand(cf *classModel, ins instruction) (memberReference, error) {
	if len(ins.Operands) != 2 {
		return memberReference{}, fmt.Errorf("invalid field operands")
	}
	index := binary.BigEndian.Uint16(ins.Operands)
	entry, err := cf.poolEntryWithTag(index, cpFieldref)
	if err != nil {
		return memberReference{}, err
	}
	_ = entry
	return cf.memberRef(index)
}

func validateClassOperand(cf *classModel, ins instruction) error {
	if len(ins.Operands) < 2 {
		return fmt.Errorf("truncated class operand")
	}
	_, err := cf.className(binary.BigEndian.Uint16(ins.Operands[:2]))
	return err
}

func classOperandName(cf *classModel, ins instruction) (string, error) {
	if len(ins.Operands) < 2 {
		return "", fmt.Errorf("truncated class operand")
	}
	return cf.className(binary.BigEndian.Uint16(ins.Operands[:2]))
}

func primitiveArrayDescriptor(arrayType byte) string {
	switch arrayType {
	case 4:
		return "[Z"
	case 5:
		return "[C"
	case 6:
		return "[F"
	case 7:
		return "[D"
	case 8:
		return "[B"
	case 9:
		return "[S"
	case 10:
		return "[I"
	case 11:
		return "[J"
	default:
		return ""
	}
}

func seededFieldValue(cf *classModel, ref memberReference, descriptor descriptorType, limits Limits) abstractValue {
	value := valueForDescriptor(descriptor)
	if ref.Owner != cf.Name {
		return value
	}
	for _, field := range cf.Fields {
		if field.Name != ref.Name || field.Descriptor != ref.Descriptor || field.Constant == nil {
			continue
		}
		if field.Constant.Kind == constantString {
			value.Kinds = kindString
			if len(field.Constant.String) <= limits.MaxConstantBytes {
				value.Constant = field.Constant.String
			}
		} else if field.Constant.Kind == constantInteger || field.Constant.Kind == constantLong ||
			field.Constant.Kind == constantFloat || field.Constant.Kind == constantDouble {
			constant := strconv.FormatInt(field.Constant.Integer, 10)
			if len(constant) <= limits.MaxConstantBytes {
				value.Constant = constant
			}
		}
		return value
	}
	return value
}

func valueForDescriptor(descriptor descriptorType) abstractValue {
	value := abstractValue{Kinds: kindUnknown, Width: descriptor.Width}
	switch descriptor.Descriptor[0] {
	case 'B', 'C', 'I', 'S', 'Z':
		value.Verifier = verifierInt
	case 'F':
		value.Verifier = verifierFloat
	case 'J':
		value.Verifier = verifierLong
	case 'D':
		value.Verifier = verifierDouble
	case 'L':
		value.Verifier, value.Reference = verifierReference, descriptor.Object
	case '[':
		value.Verifier, value.Reference = verifierReference, descriptor.Descriptor
	}
	switch descriptor.Descriptor {
	case "Ljava/lang/String;":
		value.Kinds = kindString
	case "[B":
		value.Kinds = kindBytes
	case "Ljava/io/File;", "Ljava/nio/file/Path;":
		value.Kinds = kindPath
	case "Ljava/lang/Process;":
		value.Kinds = kindProcess
	}
	return value
}

func valueCompatibleWithDescriptor(value abstractValue, descriptor descriptorType) bool {
	if descriptor.Void {
		return false
	}
	switch descriptor.Descriptor[0] {
	case 'B', 'C', 'I', 'S', 'Z':
		return value.Verifier == verifierInt
	case 'F':
		return value.Verifier == verifierFloat
	case 'J':
		return value.Verifier == verifierLong
	case 'D':
		return value.Verifier == verifierDouble
	case 'L', '[':
		return isReferenceValue(value)
	default:
		return false
	}
}

func valueAssignmentCompatible(cf *classModel, value abstractValue, descriptor descriptorType) bool {
	if !valueCompatibleWithDescriptor(value, descriptor) {
		return false
	}
	if descriptor.Descriptor[0] != 'L' && descriptor.Descriptor[0] != '[' {
		return true
	}
	if value.Verifier == verifierNull {
		return true
	}
	target := descriptor.Object
	if descriptor.Array {
		target = descriptor.Descriptor
	}
	return referenceAssignableTo(cf, value.Reference, target)
}

var knownReferenceSupers = map[string][]string{
	"java/lang/Object":                        {},
	"java/lang/String":                        {"java/lang/Object", "java/io/Serializable", "java/lang/Comparable", "java/lang/CharSequence"},
	"java/lang/Runtime":                       {"java/lang/Object"},
	"java/lang/ProcessBuilder":                {"java/lang/Object"},
	"java/lang/Process":                       {"java/lang/Object"},
	"java/io/File":                            {"java/lang/Object", "java/io/Serializable", "java/lang/Comparable"},
	"java/util/ArrayList":                     {"java/util/List", "java/util/Collection", "java/lang/Iterable", "java/lang/Object"},
	"javax/servlet/http/HttpServletRequest":   {"javax/servlet/ServletRequest", "java/lang/Object"},
	"jakarta/servlet/http/HttpServletRequest": {"jakarta/servlet/ServletRequest", "java/lang/Object"},
	"javax/servlet/ServletRequest":            {"java/lang/Object"},
	"jakarta/servlet/ServletRequest":          {"java/lang/Object"},
	"javax/servlet/jsp/PageContext":           {"java/lang/Object"},
	"jakarta/servlet/jsp/PageContext":         {"java/lang/Object"},
	"java/util/List":                          {"java/util/Collection", "java/lang/Iterable", "java/lang/Object"},
	"java/util/Collection":                    {"java/lang/Iterable", "java/lang/Object"},
	"java/lang/Throwable":                     {"java/lang/Object"},
	"java/lang/Class":                         {"java/lang/Object"},
	"java/lang/invoke/MethodType":             {"java/lang/Object"},
	"java/lang/invoke/MethodHandle":           {"java/lang/Object"},
}

var knownClosedReferenceTypes = map[string]struct{}{
	"java/lang/String": {}, "java/lang/Runtime": {}, "java/lang/ProcessBuilder": {},
	"java/lang/Class": {}, "java/lang/invoke/MethodType": {},
	"java/lang/invoke/MethodHandle": {},
}

func referenceAssignableTo(cf *classModel, source, target string) bool {
	if source == "" || source == target || target == "java/lang/Object" {
		return true
	}
	if strings.HasPrefix(source, "[") {
		return arrayReferenceAssignableTo(cf, source, target)
	}
	if strings.HasPrefix(target, "[") {
		return false
	}
	if cf != nil && source == cf.Name {
		if cf.Super == target {
			return true
		}
		for _, name := range cf.Interfaces {
			if name == target {
				return true
			}
		}
	}
	if knownReferenceReachable(source, target) {
		return true
	}
	if _, closed := knownClosedReferenceTypes[source]; closed {
		return false
	}
	if _, closed := knownClosedReferenceTypes[target]; closed {
		return false
	}
	_, sourceKnown := knownReferenceSupers[source]
	_, targetKnown := knownReferenceSupers[target]
	return !sourceKnown || !targetKnown
}

func knownReferenceReachable(source, target string) bool {
	pending := []string{source}
	seen := map[string]struct{}{source: {}}
	for len(pending) != 0 {
		current := pending[0]
		pending = pending[1:]
		for _, parent := range knownReferenceSupers[current] {
			if parent == target {
				return true
			}
			if _, ok := seen[parent]; ok {
				continue
			}
			seen[parent] = struct{}{}
			pending = append(pending, parent)
		}
	}
	return false
}

func arrayReferenceAssignableTo(cf *classModel, source, target string) bool {
	if source == target || target == "java/lang/Object" || target == "java/lang/Cloneable" || target == "java/io/Serializable" {
		return true
	}
	if !strings.HasPrefix(target, "[") || source == "[" || target == "[" {
		return source == "[" && target == "["
	}
	if _, err := parseFieldDescriptor(source); err != nil {
		return false
	}
	if _, err := parseFieldDescriptor(target); err != nil {
		return false
	}
	sourceComponent, targetComponent := source[1:], target[1:]
	sourcePrimitive := sourceComponent[0] != 'L' && sourceComponent[0] != '['
	targetPrimitive := targetComponent[0] != 'L' && targetComponent[0] != '['
	if sourcePrimitive || targetPrimitive {
		return sourcePrimitive && targetPrimitive && sourceComponent == targetComponent
	}
	return referenceAssignableTo(cf, descriptorReferenceName(sourceComponent), descriptorReferenceName(targetComponent))
}

func descriptorReferenceName(descriptor string) string {
	if strings.HasPrefix(descriptor, "L") && strings.HasSuffix(descriptor, ";") {
		return descriptor[1 : len(descriptor)-1]
	}
	return descriptor
}

func valueHasExactDescriptor(value abstractValue, descriptor descriptorType) bool {
	if !valueCompatibleWithDescriptor(value, descriptor) {
		return false
	}
	if descriptor.Descriptor[0] == '[' {
		return value.Reference == descriptor.Descriptor
	}
	if descriptor.Descriptor[0] == 'L' {
		return value.Reference == descriptor.Object
	}
	return true
}

func valueHasExactReference(value abstractValue, className string) bool {
	return value.Verifier == verifierReference && exactRuntimeType(value) == className
}

func mergedSummaryOnly(left, right abstractValue) bool {
	leftTainted := left.Taint != 0
	rightTainted := right.Taint != 0
	if !leftTainted && !rightTainted {
		return false
	}
	return (!leftTainted || left.SummaryOnly) && (!rightTainted || right.SummaryOnly)
}

func mergeSemanticValues(left, right abstractValue, limits Limits, budget *abstractBudget) (abstractValue, error) {
	if err := budget.chargeValueCopies("semantic value merge", 0, []abstractValue{left, right}, 1); err != nil {
		return abstractValue{}, err
	}
	if left.Width == 0 {
		return cloneValue(right), nil
	}
	if right.Width == 0 {
		return cloneValue(left), nil
	}
	result := cloneValue(left)
	result.Taint |= right.Taint
	result.Arguments = result.Arguments.union(right.Arguments)
	result.Kinds |= right.Kinds
	result.SummaryOnly = mergedSummaryOnly(left, right)
	result.Constant = ""
	result.Provenance = mergeProvenance(left.Provenance, right.Provenance, limits.MaxProvenanceSteps)
	return result, nil
}

func loadStoreWidth(op byte) uint8 {
	if op == 0x16 || op == 0x18 || op == 0x37 || op == 0x39 {
		return 2
	}
	return 1
}

func loadStoreVerifier(op byte) verifierType {
	switch {
	case op == 0x15 || op == 0x36 || op >= 0x1a && op <= 0x1d || op >= 0x3b && op <= 0x3e:
		return verifierInt
	case op == 0x16 || op == 0x37 || op >= 0x1e && op <= 0x21 || op >= 0x3f && op <= 0x42:
		return verifierLong
	case op == 0x17 || op == 0x38 || op >= 0x22 && op <= 0x25 || op >= 0x43 && op <= 0x46:
		return verifierFloat
	case op == 0x18 || op == 0x39 || op >= 0x26 && op <= 0x29 || op >= 0x47 && op <= 0x4a:
		return verifierDouble
	default:
		return verifierReference
	}
}

func valueMatchesLoadStore(op byte, value abstractValue) bool {
	want := loadStoreVerifier(op)
	if want == verifierReference {
		return isLocalReferenceValue(value) || value.Verifier == verifierReturnAddress
	}
	return value.Verifier == want
}

func isReferenceValue(value abstractValue) bool {
	return value.Verifier == verifierReference || value.Verifier == verifierNull
}

func isKnownNull(value abstractValue) bool {
	return value.Verifier == verifierNull || value.Nullness == nullnessNull
}

func exactRuntimeType(value abstractValue) string {
	if isKnownNull(value) {
		return ""
	}
	if value.RuntimeType != "" {
		return value.RuntimeType
	}
	if _, closed := knownClosedReferenceTypes[value.Reference]; closed {
		return value.Reference
	}
	return ""
}

func requireDereference(cf *classModel, value abstractValue, owner, operation string) error {
	if !isReferenceValue(value) {
		return fmt.Errorf("%s requires initialized reference verifier type", operation)
	}
	if isKnownNull(value) {
		return &noNormalFlowError{}
	}
	if owner == "" {
		return nil
	}
	if !referenceAssignableTo(cf, value.Reference, owner) {
		return fmt.Errorf("%s receiver type %q is incompatible with owner %s", operation, value.Reference, owner)
	}
	if runtimeType := exactRuntimeType(value); runtimeType != "" && !referenceAssignableTo(cf, runtimeType, owner) {
		return fmt.Errorf("%s exact receiver type %q is incompatible with owner %s", operation, runtimeType, owner)
	}
	return nil
}

func isLocalReferenceValue(value abstractValue) bool {
	return isReferenceValue(value) || value.Verifier == verifierUninitialized
}

func implicitLoad(op byte) (int, uint8) {
	group := int((op - 0x1a) / 4)
	index := int((op - 0x1a) % 4)
	width := uint8(1)
	if group == 1 || group == 3 {
		width = 2
	}
	return index, width
}

func implicitStore(op byte) (int, uint8) {
	group := int((op - 0x3b) / 4)
	index := int((op - 0x3b) % 4)
	width := uint8(1)
	if group == 1 || group == 3 {
		width = 2
	}
	return index, width
}

func loadLocal(f *frame, index int, width uint8, verifier verifierType, push func(abstractValue) error) error {
	if index < 0 || index >= len(f.Locals) || width == 2 && index+1 >= len(f.Locals) {
		return fmt.Errorf("local index %d is out of range", index)
	}
	value := f.Locals[index]
	if value.Width != width || width == 2 && f.Locals[index+1].Width != 0 {
		return fmt.Errorf("local %d has incompatible width %d, expected %d", index, value.Width, width)
	}
	if verifier == verifierReference {
		if !isLocalReferenceValue(value) {
			return fmt.Errorf("local %d is not a reference", index)
		}
	} else if value.Verifier != verifier {
		return fmt.Errorf("local %d has verifier type %d, expected %d", index, value.Verifier, verifier)
	}
	return push(value)
}

func storeLocal(f *frame, index int, value abstractValue, budget *abstractBudget) error {
	if index < 0 || index >= len(f.Locals) || value.Width == 2 && index+1 >= len(f.Locals) {
		return fmt.Errorf("local index %d is out of range for width %d", index, value.Width)
	}
	if index > 0 && f.Locals[index-1].Width == 2 {
		f.Locals[index-1] = abstractValue{}
	}
	if f.Locals[index].Width == 2 && index+1 < len(f.Locals) {
		f.Locals[index+1] = abstractValue{}
	}
	if budget != nil {
		if err := budget.chargeValueCopies("local value retention", 0, []abstractValue{value}, 1); err != nil {
			return err
		}
	}
	f.Locals[index] = cloneValue(value)
	if value.Width == 2 {
		f.Locals[index+1] = abstractValue{}
	}
	return nil
}

func validateIINC(f *frame, index int) error {
	if index < 0 || index >= len(f.Locals) || f.Locals[index].Width != 1 || f.Locals[index].Verifier != verifierInt {
		return fmt.Errorf("iinc local %d is unavailable or category two", index)
	}
	f.Locals[index].Constant = ""
	return nil
}

func pushValue(f *frame, value abstractValue, code *codeModel, limits Limits) error {
	if value.Width != 1 && value.Width != 2 {
		return fmt.Errorf("cannot push value of width %d", value.Width)
	}
	f.Stack = append(f.Stack, cloneValue(value))
	if stackSlots(f.Stack) > int(code.MaxStack) {
		f.Stack = f.Stack[:len(f.Stack)-1]
		return fmt.Errorf("operand stack exceeds max_stack %d", code.MaxStack)
	}
	if len(f.Locals)+stackSlots(f.Stack)+len(f.Fields)+heapSlots(f.Heap) > limits.MaxFrameSlots {
		f.Stack = f.Stack[:len(f.Stack)-1]
		return &abstractBudgetError{detail: fmt.Sprintf("frame state exceeds slot limit %d", limits.MaxFrameSlots)}
	}
	return nil
}

func popValue(f *frame, width uint8) (abstractValue, error) {
	if len(f.Stack) == 0 {
		return abstractValue{}, fmt.Errorf("operand stack underflow")
	}
	index := len(f.Stack) - 1
	value := f.Stack[index]
	if value.Width != width {
		return abstractValue{}, fmt.Errorf("operand width %d does not match expected %d", value.Width, width)
	}
	f.Stack = f.Stack[:index]
	return value, nil
}

func stackSlots(values []abstractValue) int {
	total := 0
	for _, value := range values {
		total += int(value.Width)
	}
	return total
}

func mergeFrames(left, right frame, limits Limits, budget *abstractBudget) (frame, bool, error) {
	if len(left.Locals) != len(right.Locals) {
		return frame{}, false, fmt.Errorf("incompatible local counts %d and %d", len(left.Locals), len(right.Locals))
	}
	if len(left.Stack) != len(right.Stack) || stackSlots(left.Stack) != stackSlots(right.Stack) {
		return frame{}, false, fmt.Errorf("incompatible stack height %d/%d slots and %d/%d values", stackSlots(left.Stack), stackSlots(right.Stack), len(left.Stack), len(right.Stack))
	}
	if err := budget.charge("frame merge field key scan", len(left.Fields)+len(right.Fields)); err != nil {
		return frame{}, false, err
	}
	fieldCount := len(left.Fields)
	for key := range right.Fields {
		if _, ok := left.Fields[key]; !ok {
			fieldCount++
		}
	}
	heapIDs := orderedHeapIDs(left.Heap, right.Heap)
	if len(left.Locals)+stackSlots(left.Stack)+fieldCount+len(heapIDs) > limits.MaxFrameSlots {
		return frame{}, false, &abstractBudgetError{detail: fmt.Sprintf(
			"merged frame state exceeds slot limit %d", limits.MaxFrameSlots,
		)}
	}
	upperValues := len(left.Locals) + len(left.Stack) + fieldCount
	upperCost := 1 + upperValues + fieldCount + upperValues*limits.MaxProvenanceSteps
	if err := budget.charge("frame merge", frameStateUnits(left)+frameStateUnits(right)+upperCost); err != nil {
		return frame{}, false, err
	}
	result := cloneFrame(left)
	result.Unproven = left.Unproven || right.Unproven
	result.ThisUninit = left.ThisUninit || right.ThisUninit
	for i := range result.Locals {
		if left.Locals[i].Width != right.Locals[i].Width {
			if left.Locals[i].Width != 0 && right.Locals[i].Width != 0 {
				return frame{}, false, fmt.Errorf("incompatible local width at %d", i)
			}
			result.Locals[i] = abstractValue{}
			continue
		}
		merged, mergeErr := mergeValues(left.Locals[i], right.Locals[i], limits, budget)
		if mergeErr != nil {
			return frame{}, false, mergeErr
		}
		result.Locals[i] = merged
	}
	for i := range result.Stack {
		if left.Stack[i].Width != right.Stack[i].Width {
			return frame{}, false, fmt.Errorf("incompatible stack width at %d", i)
		}
		merged, mergeErr := mergeValues(left.Stack[i], right.Stack[i], limits, budget)
		if mergeErr != nil {
			return frame{}, false, mergeErr
		}
		result.Stack[i] = merged
	}
	keys := make(map[fieldKey]struct{}, len(left.Fields)+len(right.Fields))
	for key := range left.Fields {
		keys[key] = struct{}{}
	}
	for key := range right.Fields {
		keys[key] = struct{}{}
	}
	orderedKeys, orderErr := orderedFieldKeysFromSetBudget(keys, budget)
	if orderErr != nil {
		return frame{}, false, orderErr
	}
	result.Fields = make(map[fieldKey]abstractValue, len(keys))
	for _, key := range orderedKeys {
		lv, lok := left.Fields[key]
		rv, rok := right.Fields[key]
		if !lok {
			lv = unknownLike(rv)
		}
		if !rok {
			rv = unknownLike(lv)
		}
		if lv.Width != rv.Width {
			return frame{}, false, fmt.Errorf("incompatible field width for %s.%s", key.Owner, key.Name)
		}
		merged, mergeErr := mergeValues(lv, rv, limits, budget)
		if mergeErr != nil {
			return frame{}, false, mergeErr
		}
		result.Fields[key] = merged
	}
	result.Heap = make(map[uint32]heapObject, len(heapIDs))
	for _, id := range heapIDs {
		merged, mergeErr := mergeHeapObjects(left.Heap[id], right.Heap[id], limits, budget)
		if mergeErr != nil {
			return frame{}, false, mergeErr
		}
		result.Heap[id] = merged
	}
	if len(result.Locals)+stackSlots(result.Stack)+len(result.Fields)+heapSlots(result.Heap) > limits.MaxFrameSlots {
		return frame{}, false, &abstractBudgetError{detail: fmt.Sprintf(
			"merged frame state exceeds slot limit %d", limits.MaxFrameSlots,
		)}
	}
	equal, equalErr := framesEqualBudget(left, result, budget)
	if equalErr != nil {
		return frame{}, false, equalErr
	}
	return result, !equal, nil
}

func fieldKeyLess(left, right fieldKey) bool {
	if left.ObjectID != right.ObjectID {
		return left.ObjectID < right.ObjectID
	}
	if left.Owner != right.Owner {
		return left.Owner < right.Owner
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	if left.ArrayIndexKnown != right.ArrayIndexKnown {
		return !left.ArrayIndexKnown
	}
	if left.ArrayIndex != right.ArrayIndex {
		return left.ArrayIndex < right.ArrayIndex
	}
	return left.Descriptor < right.Descriptor
}

func orderedFieldKeysBudget(fields map[fieldKey]abstractValue, budget *abstractBudget, component string) ([]fieldKey, error) {
	count := len(fields)
	if err := budget.charge(component+" retained keys", count); err != nil {
		return nil, err
	}
	for width := 1; width < count; {
		if err := budget.charge(component+" sort work", count); err != nil {
			return nil, err
		}
		if width > count/2 {
			break
		}
		width *= 2
	}
	return orderedFieldKeys(fields), nil
}

func orderedFieldKeys(fields map[fieldKey]abstractValue) []fieldKey {
	keys := make([]fieldKey, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return fieldKeyLess(keys[i], keys[j]) })
	return keys
}

func orderedFieldKeysFromSet(fields map[fieldKey]struct{}) []fieldKey {
	keys := make([]fieldKey, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return fieldKeyLess(keys[i], keys[j]) })
	return keys
}

func orderedFieldKeysFromSetBudget(fields map[fieldKey]struct{}, budget *abstractBudget) ([]fieldKey, error) {
	count := len(fields)
	if err := budget.charge("merged field key order", count); err != nil {
		return nil, err
	}
	for width := 1; width < count; width *= 2 {
		if err := budget.charge("merged field key sort", count); err != nil {
			return nil, err
		}
		if width > count/2 {
			break
		}
	}
	return orderedFieldKeysFromSet(fields), nil
}

func unknownLike(value abstractValue) abstractValue {
	return abstractValue{
		Arguments: value.Arguments, Kinds: kindUnknown, Verifier: value.Verifier, Reference: value.Reference,
		RuntimeType: value.RuntimeType, Nullness: value.Nullness,
		ArrayLength: value.ArrayLength, LengthKnown: value.LengthKnown, Width: value.Width,
	}
}

func mergeValues(left, right abstractValue, limits Limits, budget *abstractBudget) (abstractValue, error) {
	if left.Width == 0 {
		if err := budget.chargeValueCopies("merged value clone", 0, []abstractValue{right}, 1); err != nil {
			return abstractValue{}, err
		}
		return cloneValue(right), nil
	}
	if right.Width == 0 {
		if err := budget.chargeValueCopies("merged value clone", 0, []abstractValue{left}, 1); err != nil {
			return abstractValue{}, err
		}
		return cloneValue(left), nil
	}
	verifier, reference, err := mergeVerifierTypes(left, right)
	if err != nil {
		return abstractValue{}, err
	}
	result := abstractValue{
		Taint: left.Taint | right.Taint, Arguments: left.Arguments.union(right.Arguments), Kinds: left.Kinds | right.Kinds,
		Verifier: verifier, Reference: reference, RuntimeType: mergedRuntimeType(left, right),
		Nullness: mergeNullness(left.Nullness, right.Nullness), SummaryOnly: mergedSummaryOnly(left, right), Width: left.Width,
	}
	if left.Constant == right.Constant && len(left.Constant) <= limits.MaxConstantBytes {
		result.Constant = left.Constant
	}
	if left.LengthKnown && right.LengthKnown && left.ArrayLength == right.ArrayLength {
		result.ArrayLength, result.LengthKnown = left.ArrayLength, true
	}
	objectID, objectIDs, err := mergeObjectIdentities(left, right, limits, budget)
	if err != nil {
		return abstractValue{}, err
	}
	result.ObjectID = objectID
	result.ObjectIDs = objectIDs
	provenanceCopies := []abstractValue{{Provenance: left.Provenance}, {Provenance: right.Provenance}}
	if err := budget.chargeValueCopies("merged value provenance", 0, provenanceCopies, 1); err != nil {
		return abstractValue{}, err
	}
	result.Provenance = mergeProvenance(left.Provenance, right.Provenance, limits.MaxProvenanceSteps)
	return result, nil
}

func mergedRuntimeType(left, right abstractValue) string {
	leftType, rightType := exactRuntimeType(left), exactRuntimeType(right)
	if leftType == rightType {
		return leftType
	}
	if isKnownNull(left) {
		return rightType
	}
	if isKnownNull(right) {
		return leftType
	}
	return ""
}

func mergeNullness(left, right referenceNullness) referenceNullness {
	if left == right {
		return left
	}
	return nullnessUnknown
}

func mergeVerifierTypes(left, right abstractValue) (verifierType, string, error) {
	if left.Verifier == verifierTop || right.Verifier == verifierTop {
		return verifierTop, "", nil
	}
	if left.Verifier == verifierNull && right.Verifier == verifierReference {
		return verifierReference, right.Reference, nil
	}
	if right.Verifier == verifierNull && left.Verifier == verifierReference {
		return verifierReference, left.Reference, nil
	}
	if left.Verifier != right.Verifier {
		return verifierTop, "", fmt.Errorf("incompatible verifier types %d and %d", left.Verifier, right.Verifier)
	}
	if left.Verifier == verifierUninitialized {
		if left.Reference != right.Reference || left.ObjectID == 0 || left.ObjectID != right.ObjectID ||
			len(left.ObjectIDs) != 0 || len(right.ObjectIDs) != 0 {
			return verifierTop, "", fmt.Errorf("incompatible uninitialized allocation sites")
		}
		return verifierUninitialized, left.Reference, nil
	}
	if left.Verifier != verifierReference {
		return left.Verifier, "", nil
	}
	if left.Reference == right.Reference {
		return verifierReference, left.Reference, nil
	}
	if isReferenceArrayDescriptor(left.Reference) && isReferenceArrayDescriptor(right.Reference) {
		return verifierReference, "[", nil
	}
	return verifierReference, "java/lang/Object", nil
}

func isReferenceArrayDescriptor(value string) bool {
	return strings.HasPrefix(value, "[L") || strings.HasPrefix(value, "[[") || value == "["
}

func mergeObjectIdentities(
	left, right abstractValue,
	limits Limits,
	budget *abstractBudget,
) (uint32, []uint32, error) {
	count := identityCount(left)
	for i := 0; i < identityCount(right); i++ {
		id := identityAt(right, i)
		if !valueHasIdentity(left, id) {
			count++
		}
	}
	identityLimit := limits.MaxFrameSlots
	if identityLimit > 32 {
		identityLimit = 32
	}
	if count > identityLimit {
		return 0, nil, &abstractBudgetError{detail: fmt.Sprintf(
			"possible allocation identity count %d exceeds limit %d", count, identityLimit,
		)}
	}
	if count == 0 {
		return 0, nil, nil
	}
	if count == 1 {
		if identityCount(left) != 0 {
			return identityAt(left, 0), nil, nil
		}
		return identityAt(right, 0), nil, nil
	}
	if err := budget.charge("allocation identity join", count); err != nil {
		return 0, nil, err
	}
	ids := make([]uint32, 0, count)
	for i := 0; i < identityCount(left); i++ {
		ids = append(ids, identityAt(left, i))
	}
	for i := 0; i < identityCount(right); i++ {
		id := identityAt(right, i)
		if !valueHasIdentity(left, id) {
			ids = append(ids, id)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return 0, ids, nil
}

func identityCount(value abstractValue) int {
	if len(value.ObjectIDs) != 0 {
		return len(value.ObjectIDs)
	}
	if value.ObjectID != 0 {
		return 1
	}
	return 0
}

func identityAt(value abstractValue, index int) uint32 {
	if len(value.ObjectIDs) != 0 {
		return value.ObjectIDs[index]
	}
	return value.ObjectID
}

func valueHasIdentity(value abstractValue, id uint32) bool {
	if len(value.ObjectIDs) == 0 {
		return value.ObjectID == id
	}
	index := sort.Search(len(value.ObjectIDs), func(i int) bool { return value.ObjectIDs[i] >= id })
	return index < len(value.ObjectIDs) && value.ObjectIDs[index] == id
}

func cloneFrame(value frame) frame {
	result := frame{
		Locals: make([]abstractValue, len(value.Locals)), Stack: make([]abstractValue, len(value.Stack)),
		Fields: make(map[fieldKey]abstractValue, len(value.Fields)), Unproven: value.Unproven,
		Heap:       make(map[uint32]heapObject, len(value.Heap)),
		ThisUninit: value.ThisUninit,
	}
	for i := range value.Locals {
		result.Locals[i] = cloneValue(value.Locals[i])
	}
	for i := range value.Stack {
		result.Stack[i] = cloneValue(value.Stack[i])
	}
	for key, field := range value.Fields {
		result.Fields[key] = cloneValue(field)
	}
	for id, object := range value.Heap {
		result.Heap[id] = cloneHeapObject(object)
	}
	return result
}

func cloneFrameBudget(value frame, budget *abstractBudget, component string) (frame, error) {
	if err := budget.charge(component, frameStateUnits(value)); err != nil {
		return frame{}, err
	}
	return cloneFrame(value), nil
}

func frameStateUnits(value frame) int {
	units := 1 + len(value.Locals) + len(value.Stack) + len(value.Fields) + len(value.Heap)
	for _, local := range value.Locals {
		units += len(local.Provenance) + len(local.ObjectIDs)
	}
	for _, stack := range value.Stack {
		units += len(stack.Provenance) + len(stack.ObjectIDs)
	}
	for _, field := range value.Fields {
		units += len(field.Provenance) + len(field.ObjectIDs)
	}
	for _, object := range value.Heap {
		units += heapObjectStateUnits(object)
	}
	return units
}

func valueStateUnits(value abstractValue) int {
	return 1 + len(value.Provenance) + len(value.ObjectIDs)
}

func cloneValue(value abstractValue) abstractValue {
	value.Provenance = cloneProvenance(value.Provenance)
	value.ObjectIDs = append([]uint32(nil), value.ObjectIDs...)
	return value
}

func cloneProvenance(value []provenanceStep) []provenanceStep {
	return append([]provenanceStep(nil), value...)
}

func mergeProvenance(left, right []provenanceStep, limit int) []provenanceStep {
	values := append(cloneProvenance(left), right...)
	sort.Slice(values, func(i, j int) bool {
		if values[i].Offset != values[j].Offset {
			return values[i].Offset < values[j].Offset
		}
		return values[i].API < values[j].API
	})
	result := values[:0]
	for _, value := range values {
		if len(result) != 0 && result[len(result)-1] == value {
			continue
		}
		if len(result) == limit {
			break
		}
		result = append(result, value)
	}
	return append([]provenanceStep(nil), result...)
}

func appendProvenance(values []provenanceStep, step provenanceStep, limit int) []provenanceStep {
	for _, value := range values {
		if value == step {
			return cloneProvenance(values)
		}
	}
	result := cloneProvenance(values)
	if len(result) < limit {
		result = append(result, step)
	}
	return result
}

func framesEqual(left, right frame) bool {
	return reflect.DeepEqual(left, right)
}

func framesEqualBudget(left, right frame, budget *abstractBudget) (bool, error) {
	if err := budget.charge("left frame equality scan", frameStateUnits(left)); err != nil {
		return false, err
	}
	if err := budget.charge("right frame equality scan", frameStateUnits(right)); err != nil {
		return false, err
	}
	if left.Unproven != right.Unproven || left.ThisUninit != right.ThisUninit ||
		len(left.Locals) != len(right.Locals) || len(left.Stack) != len(right.Stack) ||
		len(left.Fields) != len(right.Fields) || len(left.Heap) != len(right.Heap) {
		return false, nil
	}
	compareValues := func(leftValues, rightValues []abstractValue) (bool, error) {
		for index := range leftValues {
			if index%256 == 0 {
				if err := budget.charge("frame equality cancellation poll", 0); err != nil {
					return false, err
				}
			}
			if !reflect.DeepEqual(leftValues[index], rightValues[index]) {
				return false, nil
			}
		}
		return true, nil
	}
	if equal, err := compareValues(left.Locals, right.Locals); err != nil || !equal {
		return equal, err
	}
	if equal, err := compareValues(left.Stack, right.Stack); err != nil || !equal {
		return equal, err
	}
	keys, err := orderedFieldKeysBudget(left.Fields, budget, "frame equality field")
	if err != nil {
		return false, err
	}
	for index, key := range keys {
		if index%256 == 0 {
			if err := budget.charge("frame equality field poll", 0); err != nil {
				return false, err
			}
		}
		rightValue, ok := right.Fields[key]
		if !ok || !reflect.DeepEqual(left.Fields[key], rightValue) {
			return false, nil
		}
	}
	for _, id := range orderedHeapIDs(left.Heap) {
		if !reflect.DeepEqual(left.Heap[id], right.Heap[id]) {
			return false, nil
		}
	}
	return true, nil
}

func heapSlots(heap map[uint32]heapObject) int {
	total := len(heap)
	for _, object := range heap {
		total += heapObjectStateUnits(object)
	}
	return total
}

func heapObjectStateUnits(object heapObject) int {
	units := valueStateUnits(object.Builder) + valueStateUnits(object.Stream) + len(object.List) + len(object.Map) + len(object.Lambda)
	for _, value := range object.List {
		units += valueStateUnits(value)
	}
	for _, entry := range object.Map {
		units += valueStateUnits(entry.Value)
	}
	for _, callable := range object.Lambda {
		for _, captured := range callable.Captured {
			units += valueStateUnits(captured)
		}
	}
	return units
}

func cloneHeapObject(object heapObject) heapObject {
	result := heapObject{Builder: cloneValue(object.Builder), Stream: cloneValue(object.Stream)}
	result.List = make([]abstractValue, len(object.List))
	for index := range object.List {
		result.List[index] = cloneValue(object.List[index])
	}
	result.Map = make([]heapEntry, len(object.Map))
	for index, entry := range object.Map {
		result.Map[index] = heapEntry{Key: entry.Key, KeyKnown: entry.KeyKnown, Value: cloneValue(entry.Value)}
	}
	result.Lambda = make([]lambdaValue, len(object.Lambda))
	for index, callable := range object.Lambda {
		result.Lambda[index] = lambdaValue{Target: callable.Target, Captured: make([]abstractValue, len(callable.Captured))}
		for captured := range callable.Captured {
			result.Lambda[index].Captured[captured] = cloneValue(callable.Captured[captured])
		}
	}
	return result
}

func orderedHeapIDs(heaps ...map[uint32]heapObject) []uint32 {
	set := make(map[uint32]struct{})
	for _, heap := range heaps {
		for id := range heap {
			set[id] = struct{}{}
		}
	}
	ids := make([]uint32, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func mergeHeapObjects(left, right heapObject, limits Limits, budget *abstractBudget) (heapObject, error) {
	result := heapObject{}
	var err error
	result.Builder, err = mergeSemanticValues(left.Builder, right.Builder, limits, budget)
	if err != nil {
		return heapObject{}, err
	}
	result.Stream, err = mergeSemanticValues(left.Stream, right.Stream, limits, budget)
	if err != nil {
		return heapObject{}, err
	}
	count := len(left.List)
	if len(right.List) > count {
		count = len(right.List)
	}
	if count > limits.MaxCallTargets {
		count = limits.MaxCallTargets
	}
	result.List = make([]abstractValue, count)
	for index := 0; index < count; index++ {
		var lv, rv abstractValue
		if index < len(left.List) {
			lv = left.List[index]
		}
		if index < len(right.List) {
			rv = right.List[index]
		}
		result.List[index], err = mergeSemanticValues(lv, rv, limits, budget)
		if err != nil {
			return heapObject{}, err
		}
	}
	result.Map = make([]heapEntry, len(left.Map))
	for index, entry := range left.Map {
		result.Map[index] = heapEntry{Key: entry.Key, KeyKnown: entry.KeyKnown, Value: cloneValue(entry.Value)}
	}
	for _, entry := range right.Map {
		matched := false
		for index := range result.Map {
			if result.Map[index].Key == entry.Key && result.Map[index].KeyKnown == entry.KeyKnown {
				result.Map[index].Value, err = mergeSemanticValues(result.Map[index].Value, entry.Value, limits, budget)
				if err != nil {
					return heapObject{}, err
				}
				matched = true
				break
			}
		}
		if !matched && len(result.Map) < limits.MaxCallTargets {
			result.Map = append(result.Map, heapEntry{Key: entry.Key, KeyKnown: entry.KeyKnown, Value: cloneValue(entry.Value)})
		}
	}
	sort.Slice(result.Map, func(i, j int) bool {
		if result.Map[i].KeyKnown != result.Map[j].KeyKnown {
			return !result.Map[i].KeyKnown
		}
		return result.Map[i].Key < result.Map[j].Key
	})
	result.Lambda = make([]lambdaValue, len(left.Lambda))
	for index, callable := range left.Lambda {
		result.Lambda[index] = lambdaValue{Target: callable.Target, Captured: make([]abstractValue, len(callable.Captured))}
		for captured := range callable.Captured {
			result.Lambda[index].Captured[captured] = cloneValue(callable.Captured[captured])
		}
	}
	for _, callable := range right.Lambda {
		if len(result.Lambda) == limits.MaxCallTargets {
			break
		}
		duplicate := false
		for _, existing := range result.Lambda {
			if reflect.DeepEqual(existing, callable) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			result.Lambda = append(result.Lambda, cloneLambdaValue(callable))
		}
	}
	return result, nil
}

func cloneLambdaValue(callable lambdaValue) lambdaValue {
	result := lambdaValue{Target: callable.Target, Captured: make([]abstractValue, len(callable.Captured))}
	for index := range callable.Captured {
		result.Captured[index] = cloneValue(callable.Captured[index])
	}
	return result
}

func unknownValue(width uint8) abstractValue {
	return abstractValue{Kinds: kindUnknown, Verifier: verifierTop, Width: width}
}

func constantValueAbstract(value string, verifier verifierType, width uint8, limits Limits) abstractValue {
	result := abstractValue{Kinds: kindUnknown, Verifier: verifier, Width: width}
	if len(value) <= limits.MaxConstantBytes {
		result.Constant = value
	}
	return result
}

func allocationObjectID(offset uint32) uint32 {
	if offset == math.MaxUint32-1 {
		return math.MaxUint32 - 1
	}
	return offset + 1
}

func parameterObjectID(local int) uint32 {
	return math.MaxUint32 - 1 - uint32(local)
}

func isExecutionTainted(value taint) bool {
	return value&(taintRequestParameter|taintRequestHeader|taintRequestBody|taintCookie|taintSession|taintApplication) != 0
}

func executionInput(value abstractValue, analysis *methodAnalysis) bool {
	return isExecutionTainted(value.Taint) || analysis != nil && analysis.summarizing && !value.Arguments.empty()
}

func shortAPI(ref memberReference) string {
	owner := ref.Owner
	if index := strings.LastIndexByte(owner, '/'); index >= 0 {
		owner = owner[index+1:]
	}
	return owner + "." + ref.Name
}

func provenanceLess(left, right []provenanceStep) bool {
	if len(right) == 0 {
		return true
	}
	return fmt.Sprint(left) < fmt.Sprint(right)
}

func frameAlternativeLimit(limits Limits) int {
	limit := limits.MaxFrameSlots
	if limit > 32 {
		limit = 32
	}
	if limit < 1 {
		return 1
	}
	return limit
}

func isNormalSuccessor(block *basicBlock, successor uint32) bool {
	last := block.Instructions[len(block.Instructions)-1]
	for _, target := range last.Targets {
		if target == successor {
			return true
		}
	}
	if last.Fallthrough {
		end, ok := instructionEnd(last)
		return ok && end == successor
	}
	return false
}
