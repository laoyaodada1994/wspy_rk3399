################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tmp/mqtt/src/DataProcess/host_ctrl.c \
../src/tmp/mqtt/src/DataProcess/host_qurey.c 

OBJS += \
./src/tmp/mqtt/src/DataProcess/host_ctrl.o \
./src/tmp/mqtt/src/DataProcess/host_qurey.o 

C_DEPS += \
./src/tmp/mqtt/src/DataProcess/host_ctrl.d \
./src/tmp/mqtt/src/DataProcess/host_qurey.d 


# Each subdirectory must supply rules for building sources it contributes
src/tmp/mqtt/src/DataProcess/%.o: ../src/tmp/mqtt/src/DataProcess/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	aarch64-linux-gnu-gcc -std=gnu99 -D_BSD_SOURCE_ -DLINUX -I"/home/lpz/eclipse-workspace/rk3399-zk/src/application" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/DataProcess" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/JSON" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/Mqtt" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/pcap" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/shell" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/utils" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


