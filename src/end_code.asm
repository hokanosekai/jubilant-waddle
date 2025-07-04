public __end_code

inject segment read execute

    __end_code label QWORD
        dq 0        ; patched with offset of main_payload

inject ends

END