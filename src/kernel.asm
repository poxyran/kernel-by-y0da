.386
.model flat,stdcall
option casemap:none

INCLUDE    \masm32\include\windows.inc

INCLUDE    \masm32\include\comdlg32.inc
INCLUDELIB \masm32\lib\comdlg32.lib

; ------ STRUCTS ------
sSEH STRUCT
	OrgEsp            DD ?
	OrgEbp            DD ?
	SaveEip           DD ?
sSEH ENDS

; ------ EQU'S ------
MIN_KERNEL_SEARCH_BASE    EQU 070000000h
MAX_API_STRING_LENGTH     EQU 150

; ------ CONST ------
.CONST
szLoadLibrary             DB "LoadLibraryA",0
szGetProcAddress          DB "GetProcAddress",0
szExitProcess             DB "ExitProcess",0

szUser32                  DB "user32",0
szMessageBox              DB "MessageBoxA",0
szwsprintf                DB "wsprintfA",0

szInfoCap                 DB "- Kernel -",0
szInfoText                DB "The following information were obtained",13,10
                          DB "without the help of an Import Table !",13,10
		          DB 13,10
                          DB "Kernel32.dll ImageBase:  0x%08lX",13,10
                          DB "User32.dll ImageBase:  0x%08lX",13,10
		          DB 13,10
                          DB "API Addresses:",13,10
                          DB "LoadLibraryA:  0x%08lX",13,10
                          DB "GetProcAddress:  0x%08lX",13,10
                          DB "ExitProcess:  0x%08lX",13,10
                          DB 13,10
                          DB "MessageBoxA:  0x%08lX",13,10
                          DB "wsprintfA:  0x%08lX",0

; ------ DATA ------
.DATA
_LoadLibrary              DD 0
_GetProcAddress           DD 0
_ExitProcess              DD 0
_MessageBox               DD 0
_wsprintf                 DD 0

cBuff     		  DB 200 DUP (0)
SEH                       sSEH <0>
dwKernelBase              DD 0
dwUserBase                DD 0

; ------ CODE ------
.CODE
main:
	ASSUME FS : NOTHING
	
	;INT 3
	
	;---- GET ImageBase of kernel32.dll ----	
	PUSH [ESP]
	CALL GetKernelBase
	OR   EAX, EAX
	JZ   QUIT
	MOV  dwKernelBase, EAX
	
	;---- GET SOME KERNEL API ADDRESSES ----
	;-> LoadLibraryA
	PUSH OFFSET szLoadLibrary
	PUSH dwKernelBase
	CALL GetProcAddr
	OR   EAX, EAX
	JZ   QUIT
	MOV  _LoadLibrary, EAX
	
	;-> GetProcAddress
	PUSH OFFSET szGetProcAddress
	PUSH dwKernelBase
	CALL GetProcAddr
	OR   EAX, EAX
	JZ   QUIT
	MOV  _GetProcAddress, EAX
	
	;-> ExitProcess
	PUSH OFFSET szExitProcess
	PUSH dwKernelBase
	CALL GetProcAddr
	OR   EAX, EAX
	JZ   QUIT
	MOV  _ExitProcess, EAX
	
	;---- LOAD USER32.DLL ----
	PUSH OFFSET szUser32
	CALL _LoadLibrary
	OR   EAX, EAX
	JZ   QUIT
	MOV  dwUserBase, EAX
	
	;---- GET SOME USER API ADDRESSES ----
	;-> MessageBoxA
	PUSH OFFSET szMessageBox
	PUSH dwUserBase
	CALL GetProcAddr
	OR   EAX, EAX
	JZ   QUIT
	MOV  _MessageBox, EAX
	
	;-> wsprintfA
	PUSH OFFSET szwsprintf
	PUSH dwUserBase
	CALL GetProcAddr
	OR   EAX, EAX
	JZ   QUIT
	MOV  _wsprintf, EAX
	
	;---- BUILD AND SHOW THE INFORMATION MSG ----
	PUSH _wsprintf
	PUSH _MessageBox
	PUSH _ExitProcess
	PUSH _GetProcAddress
	PUSH _LoadLibrary
	PUSH dwUserBase
	PUSH dwKernelBase
	
	PUSH OFFSET szInfoText
	PUSH OFFSET cBuff
	CALL _wsprintf
	ADD  ESP, (9 * SIZEOF(DWORD))
	
	PUSH MB_ICONINFORMATION OR MB_SYSTEMMODAL
	PUSH OFFSET szInfoCap
	PUSH OFFSET cBuff
	PUSH 0
	CALL _MessageBox
	
	;---- EXIT ----
	CALL _ExitProcess							;)

QUIT:
	RET									; exit to OS
	
;---- AN UNUSED IMPORT ----
; The Win32 Loader of Win2k (maybe also of WinNT) won't call the EntryPoint of files which don't
; have an Import Table :(
; So here's an unused Import to make MASM compile an Import Table.

	PUSH NULL
	CALL GetOpenFileName
	
; ------ ROUTINES ------
; returns NULL in the case of an error
GetKernelBase PROC USES EDI ESI, dwTopStack : DWORD
	; install SEH frame
	PUSH OFFSET SehHandler
	PUSH FS:[0]
	MOV  SEH.OrgEsp, ESP
	MOV  SEH.OrgEbp, EBP
	MOV  SEH.SaveEip, OFFSET ExceptCont
	MOV  FS:[0], ESP
	
	; start the search
	MOV  EDI, dwTopStack
	AND  EDI, 0FFFF0000h		; wipe the LOWORD !
	.WHILE TRUE
	   .IF WORD PTR [EDI] == IMAGE_DOS_SIGNATURE
	      MOV  ESI, EDI
	      ADD  ESI, [ESI+03Ch]
	      .IF  DWORD PTR [ESI] == IMAGE_NT_SIGNATURE
	         .BREAK
	      .ENDIF
	   .ENDIF
           ExceptCont:
	   SUB  EDI, 010000h
	   .IF EDI < MIN_KERNEL_SEARCH_BASE
	      MOV  EDI, 0BFF70000h
	      .BREAK
	   .ENDIF
	.ENDW
	XCHG EAX, EDI	
	
	; shutdown SEH frame
	POP  FS:[0]
	ADD  ESP, 4
	RET
GetKernelBase ENDP

; returns address or NULL in the case of an error
GetProcAddr PROC USES ESI EDI ECX EBX EDX, dwDllBase : DWORD, szApi : LPSTR
	; install SEH frame
	PUSH OFFSET SehHandler
	PUSH FS:[0]
	MOV  SEH.OrgEsp, ESP
	MOV  SEH.OrgEbp, EBP
	MOV  SEH.SaveEip, OFFSET @@BadExit
	MOV  FS:[0], ESP
	
	; check PE Signarue
	MOV  ESI, dwDllBase
	CMP  WORD PTR [ESI], IMAGE_DOS_SIGNATURE
	JNZ @@BadExit
	ADD  ESI, [ESI+03Ch]
	CMP  DWORD PTR [ESI], IMAGE_NT_SIGNATURE
	JNZ @@BadExit
	
	; get the string length of the target Api
	MOV  EDI, szApi
	MOV  ECX, MAX_API_STRING_LENGTH
	XOR  AL, AL
	REPNZ  SCASB
	MOV  ECX, EDI
	SUB  ECX, szApi							; ECX -> Api string length
	
	; trace the export table
	MOV  EDX, [ESI+078h]						; EDX -> Export table
	ADD  EDX, dwDllBase
	ASSUME EDX : PTR IMAGE_EXPORT_DIRECTORY
	MOV  EBX, [EDX].AddressOfNames					; EBX -> AddressOfNames array pointer
	ADD  EBX, dwDllBase
	XOR  EAX, EAX							; EAX AddressOfNames Index
	.REPEAT
	   MOV  EDI, [EBX]
	   ADD  EDI, dwDllBase
	   MOV  ESI, szApi
	   PUSH ECX				; save the api string length
	   REPZ CMPSB
	   .IF ZERO?
	      ADD  ESP, 4
	      .BREAK
	   .ENDIF
	   POP  ECX
	   ADD  EBX, 4
	   INC  EAX   
	.UNTIL EAX == [EDX].NumberOfNames
	
	; did we found sth ?
	.IF EAX == [EDX].NumberOfNames
	   JMP @@BadExit
	.ENDIF
	
	; find the corresponding Ordinal
	MOV  ESI, [EDX].AddressOfNameOrdinals
	ADD  ESI, dwDllBase
	PUSH EDX			; save the export table pointer
	MOV  EBX, 2
	XOR  EDX, EDX
	MUL  EBX
	POP  EDX
	ADD  EAX, ESI
	XOR  ECX, ECX
	MOV  WORD PTR CX, [EAX]						; ECX -> Api Ordinal
	
	; get the address of the api
	MOV  EDI, [EDX].AddressOfFunctions
	XOR  EDX, EDX
	MOV  EBX, 4
	MOV  EAX, ECX
	MUL  EBX
	ADD  EAX, dwDllBase
	ADD  EAX, EDI
	MOV  EAX, [EAX]
	ADD  EAX, dwDllBase
	JMP  @@ExitProc
	
	ASSUME EDX : NOTHING	
		
   @@BadExit:
   	XOR  EAX, EAX   
   @@ExitProc:
	; shutdown SEH frame
	POP  FS:[0]
	ADD  ESP, 4
	RET
GetProcAddr ENDP

SehHandler PROC C pExcept:DWORD,pFrame:DWORD,pContext:DWORD,pDispatch:DWORD
	MOV  EAX, pContext
	ASSUME EAX : PTR CONTEXT
	PUSH SEH.SaveEip
	POP  [EAX].regEip
	PUSH SEH.OrgEsp
	POP  [EAX].regEsp
	PUSH SEH.OrgEbp
	POP  [EAX].regEbp
	MOV  EAX, ExceptionContinueExecution
	RET
SehHandler ENDP

end main