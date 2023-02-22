from ...util import BASE_FEE_RECIPIENT, FQ
from ..instruction import Instruction, Transition
from ..table import BlockContextFieldTag, CallContextFieldTag, TxContextFieldTag

def base_fee_hook(instruction: Instruction):
    tx_id = instruction.call_context_lookup(CallContextFieldTag.TxId)
    tx_gas = instruction.tx_context_lookup(tx_id, TxContextFieldTag.Gas)
    
    base_fee = instruction.block_context_lookup(BlockContextFieldTag.BaseFee)
    gas_used = tx_gas.expr() - instruction.curr.gas_left.expr()
    mul_base_fee_by_gas_used, carry = instruction.mul_word_by_u64(base_fee, gas_used)
    
    instruction.add_balance(FQ(BASE_FEE_RECIPIENT), [mul_base_fee_by_gas_used])
    instruction.constrain_step_state_transition(rw_counter=Transition.delta(2))
