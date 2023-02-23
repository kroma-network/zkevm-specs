from ...util import FQ, DEPOSIT_TX_TYPE
from ..execution_state import ExecutionState
from ..instruction import Instruction, Transition
from ..table import L1BlockFieldTag, CallContextFieldTag, TxContextFieldTag, TxReceiptFieldTag

def end_deposit_tx(instruction: Instruction):
    tx_id = instruction.call_context_lookup(CallContextFieldTag.TxId)
    is_persistent = instruction.call_context_lookup(CallContextFieldTag.IsPersistent)
    
    tx_type = instruction.tx_context_lookup(tx_id, TxContextFieldTag.Type)
    instruction.constrain_equal(tx_type, FQ(DEPOSIT_TX_TYPE))
    
    is_first_tx = tx_id == 1
    tx_gas = instruction.tx_context_lookup(tx_id, TxContextFieldTag.Gas)
    gas_used = 0 if is_first_tx else tx_gas

    # constrain tx status matches with `PostStateOrStatus` of TxReceipt tag in RW
    instruction.constrain_equal(
        is_persistent, instruction.tx_receipt_write(tx_id, TxReceiptFieldTag.PostStateOrStatus)
    )
    # constrain log id matches with `LogLength` of TxReceipt tag in RW
    log_id = instruction.tx_receipt_write(tx_id, TxReceiptFieldTag.LogLength)
    instruction.constrain_equal(log_id, instruction.curr.log_id)

    # constrain `CumulativeGasUsed` of TxReceipt tag in RW
    if is_first_tx:
        current_cumulative_gas_used = FQ(0)
    else:
        current_cumulative_gas_used = instruction.tx_receipt_read(
            tx_id - FQ(1), TxReceiptFieldTag.CumulativeGasUsed
        ).expr()
        
    instruction.constrain_equal(
        current_cumulative_gas_used + gas_used,
        instruction.tx_receipt_write(tx_id, TxReceiptFieldTag.CumulativeGasUsed),
    )

    if is_first_tx:
        instruction.l1_block_write(L1BlockFieldTag.L1BaseFee)
        instruction.l1_block_write(L1BlockFieldTag.L1FeeOverhead)
        instruction.l1_block_write(L1BlockFieldTag.L1FeeScalar)
    
    # When to next transaction
    if instruction.next.execution_state == ExecutionState.BeginTx:
        # Check next tx_id is increased by 1
        instruction.constrain_equal(
            instruction.call_context_lookup(
                CallContextFieldTag.TxId, call_id=instruction.next.rw_counter
            ),
            tx_id.expr() + 1,
        )
        # Do step state transition for rw_counter
        # 5 + (1-is_first_tx) + 3*is_first_tx + 1 = 7 + 2*is_first_tx
        instruction.constrain_step_state_transition(rw_counter=Transition.delta(7 + 2*is_first_tx))

    # When to end of block
    if instruction.next.execution_state == ExecutionState.EndBlock:
        # Do step state transition for rw_counter and call_id
        instruction.constrain_step_state_transition(
            rw_counter=Transition.delta(6 + 2*is_first_tx), call_id=Transition.same()
        )
