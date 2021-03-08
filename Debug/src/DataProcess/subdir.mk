################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables
C_SRCS += \
../src/DataProcess/DataProcess.c \
../src/DataProcess/host_ctrl.c \
../src/DataProcess/host_qurey.c

OBJS += \
./src/DataProcess/DataProcess.o \
./src/DataProcess/host_ctrl.o \
./src/DataProcess/host_qurey.o

C_DEPS += \
./src/DataProcess/DataProcess.d \
./src/DataProcess/host_ctrl.d \
./src/DataProcess/host_qurey.d


# Each subdirectory must supply rules for building sources it contributes
src/DataProcess/%.o: ../src/DataProcess/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	aarch64-linux-gnu-gcc -std=gnu99 -D_BSD_SOURCE_  -DZRRJ -DLINUX -I"/home/projects/wspy_rk3399/src/application" -I"/home/projects/wspy_rk3399/src/DataProcess" -I"/home/projects/wspy_rk3399/src/JSON" -I"/home/projects/wspy_rk3399/src/Mqtt" -I"/home/projects/wspy_rk3399/src/pcap" -I"/home/projects/wspy_rk3399/src/shell" -I"/home/projects/wspy_rk3399/src/utils" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
