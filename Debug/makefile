################################################################################
# Automatically-generated file. Do not edit!
################################################################################

-include ../makefile.init

RM := rm -rf

# All of the sources participating in the build are defined here
-include sources.mk
-include src/utils/subdir.mk
-include src/shell/subdir.mk
-include src/application/subdir.mk
-include src/Mqtt/subdir.mk
-include src/JSON/subdir.mk
-include src/DataProcess/subdir.mk
-include src/subdir.mk
-include subdir.mk
-include objects.mk

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif

-include ../makefile.defs

# Add inputs and outputs from these tool invocations to the build variables

# All Target
all: rk3399-zk

# Tool invocations
rk3399-zk: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: Cross GCC Linker'
	aarch64-linux-gnu-gcc -L"/home/projects/wspy_rk3399/lib" -o "rk3399-zk" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

# Other Targets
clean:
	-$(RM) $(EXECUTABLES)$(OBJS)$(C_DEPS) rk3399-zk
	-@echo ' '

.PHONY: all clean dependents

-include ../makefile.targets
