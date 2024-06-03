# @Author: ronan
# @Date:   09-08-2016
# @Last modified by:   ronan
# @Last modified time: 20-07-2020
# @License: GPL

#IDIR is dir with includes (.h)
#ODIR is output dir with .o
#SDIR is dir with sources (.c, .s)
#BIN is dir with output files (.elf, .bin, .list)
IDIR =./inc
ODIR =./obj
SDIR =./src
BIN = ./bin

TC= arm-none-eabi-
OPTIM = -O1

# Specify the compiler to use
CC=$(TC)gcc
# Specify the assembler to use
AS=$(TC)as
# Specity the linker to use
# LD=arm-none-eabi-ld
LD=$(TC)gcc

OBJDUMP = $(TC)objdump
OBJCOPY = $(TC)objcopy

#Targeting STM32F1
TARGET = -mcpu=cortex-m3 -mthumb

#Compilation flags
CFLAGS += -I$(IDIR)
CFLAGS += $(TARGET)
#Debug symbols
#CFLAGS += -g
#Optimizations
CFLAGS += $(OPTIM)

#Say where to look for some kinds of files
vpath %.c $(SDIR)
vpath %.s $(SDIR)

#Linker flags
LFLAGS = $(TARGET) $(OPTIM) --specs=nosys.specs

#Dependencies
_DEPS = pin.h
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

#Object files to link
_OBJ = main.o pin.o start.o ass.o nvm.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))
.SECONDARY: $(OBJ)

TARGET_NAME = pin

LFLAGS += -L ../L4/hmac_lib -lsha256
CFLAGS += -I ../L4/hmac_lib


$(TARGET_NAME): $(BIN)/$(TARGET_NAME).elf $(BIN)/$(TARGET_NAME).bin $(BIN)/$(TARGET_NAME).list;
	@echo OK

#Linker rule using specified linker script
%.elf: $(OBJ) $(DEPS) $(BIN) $(ODIR)
	@echo Linking...
	@$(LD) $(OBJ) -T $(SDIR)/linker_script.ld $(LFLAGS) -o $@

%.bin: %.elf $(BIN)
	@$(OBJCOPY) -O binary $< $@
	

%.list: %.elf $(BIN)
	@$(OBJDUMP) -S $< > $@

#C compilation rule
$(ODIR)/%.o: %.c $(DEPS)
	@echo CC $<
	@$(CC) -c -o $@ $< $(CFLAGS)

#Asssembly compilation rule
$(ODIR)/%.o: %.s $(DEPS)
	@echo AS $<
	@$(AS) $(ASFLAGS) $< $(TARGET) -o $@


$(ODIR):
	mkdir -p $(ODIR)

$(BIN):
	mkdir -p $@

#Cleaning
.PHONY: clean
clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
	rm $(BIN)/*

