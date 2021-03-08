################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables
C_SRCS += \
../src/main.c

OBJS += \
./src/main.o

C_DEPS += \
./src/main.d


# Each subdirectory must supply rules for building sources it contributes
src/%.o: ../src/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	aarch64-linux-gnu-gcc -std=gnu99 -D_BSD_SOURCE_  -DZRRJ -DLINUX -I"/home/projects/wspy_rk3399/src/application" -I"/home/projects/wspy_rk3399/src/DataProcess" -I"/home/projects/wspy_rk3399/src/JSON" -I"/home/projects/wspy_rk3399/src/Mqtt" -I"/home/projects/wspy_rk3399/src/pcap" -I"/home/projects/wspy_rk3399/src/shell" -I"/home/projects/wspy_rk3399/src/utils" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
