from ...util import FQ, N_BYTES_GAS, MAX_REFUND_QUOTIENT_OF_GAS_USED, DEPOSIT_TX_TYPE
from ..execution_state import ExecutionState
from ..instruction import Instruction, Transition
from ..table import L1BlockFieldTag, CallContextFieldTag, TxContextFieldTag, TxReceiptFieldTag

def end_deposit_tx(instruction: Instruction):
    tx_id = instruction.call_context_lookup(CallContextFieldTag.TxId)
    is_persistent = instruction.call_context_lookup(CallContextFieldTag.IsPersistent)
    is_tx_invalid = instruction.tx_context_lookup(tx_id, TxContextFieldTag.TxInvalid)

    tx_type = instruction.tx_context_lookup(tx_id, TxContextFieldTag.Type)
    instruction.constrain_equal(tx_type, FQ(DEPOSIT_TX_TYPE))

    tx_gas = instruction.tx_context_lookup(tx_id, TxContextFieldTag.Gas)
    gas_used = tx_gas
    max_refund, _ = instruction.constant_divmod(
        gas_used, FQ(MAX_REFUND_QUOTIENT_OF_GAS_USED), N_BYTES_GAS
    )
    refund = instruction.tx_refund_read(tx_id)
    effective_refund = instruction.min(max_refund, refund, 8)

    # Add effective_refund * gas_price back to caller's balance
    tx_gas_price = instruction.tx_gas_price(tx_id)
    value, carry = instruction.mul_word_by_u64(
        tx_gas_price, effective_refund
    )
    instruction.constrain_zero(carry)
    tx_caller_address = instruction.tx_context_lookup(tx_id, TxContextFieldTag.CallerAddress)
    instruction.add_balance(tx_caller_address, [value])

    # NOTE(chokobole): For deposit tx, it doesn't send a tip to coinbase.

    # constrain tx status matches with `PostStateOrStatus` of TxReceipt tag in RW
    instruction.constrain_equal(
        (1 - is_tx_invalid.expr()) * is_persistent,
        instruction.tx_receipt_write(tx_id, TxReceiptFieldTag.PostStateOrStatus),
    )

    # constrain log id matches with `LogLength` of TxReceipt tag in RW
    log_id = instruction.tx_receipt_write(tx_id, TxReceiptFieldTag.LogLength)
    instruction.constrain_equal(log_id, instruction.curr.log_id)
    # log_id is 0 if tx is invalid.
    if is_tx_invalid == 1:
        instruction.constrain_zero(log_id)

    # constrain `CumulativeGasUsed` of TxReceipt tag in RW
    is_first_tx = tx_id == 1
    if is_first_tx:  # check if it is the first tx
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
        # NOTE(chokobole): Compared to end_tx, the rwc is different as follows.
        # - instruction.add_balance(coinbase, [reward])
        # + instruction.l1_block_write(L1BlockFieldTag.L1BaseFee)
        # + instruction.l1_block_write(L1BlockFieldTag.L1FeeOverhead)
        # + instruction.l1_block_write(L1BlockFieldTag.L1FeeScalar)
        instruction.constrain_step_state_transition(rw_counter=Transition.delta(9 + 2*is_first_tx))

    # When to end of block
    if instruction.next.execution_state == ExecutionState.EndBlock:
        # Do step state transition for rw_counter and call_id
        # NOTE(chokobole): Compared to end_tx, the rwc is different as follows.
        # - instruction.add_balance(coinbase, [reward])
        # + instruction.l1_block_write(L1BlockFieldTag.L1BaseFee)
        # + instruction.l1_block_write(L1BlockFieldTag.L1FeeOverhead)
        # + instruction.l1_block_write(L1BlockFieldTag.L1FeeScalar)
        instruction.constrain_step_state_transition(
            rw_counter=Transition.delta(8 + 2*is_first_tx), call_id=Transition.same()
        )
