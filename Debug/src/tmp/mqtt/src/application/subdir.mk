################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../src/tmp/mqtt/src/application/gimbal.c \
../src/tmp/mqtt/src/application/gps.c \
../src/tmp/mqtt/src/application/mac80211_atk.c \
../src/tmp/mqtt/src/application/mmget.c \
../src/tmp/mqtt/src/application/scan_hided_ssid.c \
../src/tmp/mqtt/src/application/status.c \
../src/tmp/mqtt/src/application/wifi_access.c \
../src/tmp/mqtt/src/application/wifi_decrypt.c \
../src/tmp/mqtt/src/application/wifi_sniffer.c \
../src/tmp/mqtt/src/application/wifi_trojan.c \
../src/tmp/mqtt/src/application/wlan_list.c 

OBJS += \
./src/tmp/mqtt/src/application/gimbal.o \
./src/tmp/mqtt/src/application/gps.o \
./src/tmp/mqtt/src/application/mac80211_atk.o \
./src/tmp/mqtt/src/application/mmget.o \
./src/tmp/mqtt/src/application/scan_hided_ssid.o \
./src/tmp/mqtt/src/application/status.o \
./src/tmp/mqtt/src/application/wifi_access.o \
./src/tmp/mqtt/src/application/wifi_decrypt.o \
./src/tmp/mqtt/src/application/wifi_sniffer.o \
./src/tmp/mqtt/src/application/wifi_trojan.o \
./src/tmp/mqtt/src/application/wlan_list.o 

C_DEPS += \
./src/tmp/mqtt/src/application/gimbal.d \
./src/tmp/mqtt/src/application/gps.d \
./src/tmp/mqtt/src/application/mac80211_atk.d \
./src/tmp/mqtt/src/application/mmget.d \
./src/tmp/mqtt/src/application/scan_hided_ssid.d \
./src/tmp/mqtt/src/application/status.d \
./src/tmp/mqtt/src/application/wifi_access.d \
./src/tmp/mqtt/src/application/wifi_decrypt.d \
./src/tmp/mqtt/src/application/wifi_sniffer.d \
./src/tmp/mqtt/src/application/wifi_trojan.d \
./src/tmp/mqtt/src/application/wlan_list.d 


# Each subdirectory must supply rules for building sources it contributes
src/tmp/mqtt/src/application/%.o: ../src/tmp/mqtt/src/application/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	aarch64-linux-gnu-gcc -std=gnu99 -D_BSD_SOURCE_ -DLINUX -I"/home/lpz/eclipse-workspace/rk3399-zk/src/application" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/DataProcess" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/JSON" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/Mqtt" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/pcap" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/shell" -I"/home/lpz/eclipse-workspace/rk3399-zk/src/utils" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


