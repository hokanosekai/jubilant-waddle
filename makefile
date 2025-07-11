.default: help

CC = cl.exe
AS = ml64.exe
LD = link.exe

CFLAGS = /c
ASFLAGS = /c
LDFLAGS = /subsystem:console /MACHINE:X64 /MAP:build/yharnam.map /LARGEADDRESSAWARE:NO

OUTPUT = yharnam.exe

TARGET = C:\Windows\System32\calc.exe

SOURCE_PATH = src
OUTPUT_PATH = build

OBJS = $(OUTPUT_PATH)/injector.obj $(OUTPUT_PATH)/start_code.obj $(OUTPUT_PATH)/payload.obj $(OUTPUT_PATH)/end_code.obj 

clean:
	@echo Cleaning up build artifacts...
	del /Q $(OUTPUT_PATH)\*.obj *.pdb $(OUTPUT_PATH)\*.exe

.prepare_build:
	@echo Preparing build environment...
	if not exist $(OUTPUT_PATH) mkdir $(OUTPUT_PATH)

$(OUTPUT): $(OBJS)
	$(LD) $(LDFLAGS) /out:$(OUTPUT_PATH)/$@ $(OBJS)

$(OUTPUT_PATH)/injector.obj: $(SOURCE_PATH)/injector.c
	$(CC) $(CFLAGS) /Fo$@ $(SOURCE_PATH)/injector.c

$(OUTPUT_PATH)/payload.obj: $(SOURCE_PATH)/payload.c
	$(CC) $(CFLAGS) /Fo$@ $(SOURCE_PATH)/payload.c

$(OUTPUT_PATH)/start_code.obj: $(SOURCE_PATH)/start_code.asm
	$(AS) $(ASFLAGS) /Fo$@ $(SOURCE_PATH)/start_code.asm

$(OUTPUT_PATH)/end_code.obj: $(SOURCE_PATH)/end_code.asm
	$(AS) $(ASFLAGS) /Fo$@ $(SOURCE_PATH)/end_code.asm

build: .prepare_build $(OUTPUT)

.prepare_inject:
	@echo Preparing injector...
	copy /Y $(TARGET) target.exe
	@dir

inject: .prepare_inject
	@echo Injecting payload...
	$(OUTPUT_PATH)\$(OUTPUT) target.exe
	@dir

prepare: .prepare_build .prepare_inject

all: clean build inject

help:
	@echo Usage: nmake /f Makefile [target]
	@echo Targets:
	@echo   help		- Display this help message
	@echo   all			- Clean, build, and inject
	@echo   prepare	- Prepare the build and injector environment
	@echo   build		- Build the executable
	@echo   inject	- Inject the payload
	@echo   clean		- Remove artifacts


.PHONY: all clean help inject output .prepare_inject