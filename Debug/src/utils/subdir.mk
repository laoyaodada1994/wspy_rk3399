################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables
C_SRCS += \
../src/utils/common.c \
../src/utils/crc32.c \
../src/utils/parse.c \
../src/utils/radiotap.c \
../src/utils/serialport.c \
../src/utils/sys_log.c \
../src/utils/sys_utils.c \

OBJS += \
./src/utils/common.o \
./src/utils/crc32.o \
./src/utils/parse.o \
./src/utils/radiotap.o \
./src/utils/serialport.o \
./src/utils/sys_log.o \
./src/utils/sys_utils.o \

C_DEPS += \
./src/utils/common.d \
./src/utils/crc32.d \
./src/utils/parse.d \
./src/utils/radiotap.d \
./src/utils/serialport.d \
./src/utils/sys_log.d \
./src/utils/sys_utils.d \


# Each subdirectory must supply rules for building sources it contributes
src/utils/%.o: ../src/utils/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	aarch64-linux-gnu-gcc -std=gnu99 -D_BSD_SOURCE_  -DZRRJ -DLINUX -I"/home/projects/wspy_rk3399/src/application" -I"/home/projects/wspy_rk3399/src/DataProcess" -I"/home/projects/wspy_rk3399/src/JSON" -I"/home/projects/wspy_rk3399/src/Mqtt" -I"/home/projects/wspy_rk3399/src/pcap" -I"/home/projects/wspy_rk3399/src/shell" -I"/home/projects/wspy_rk3399/src/utils" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
