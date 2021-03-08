################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables
C_SRCS += \
../src/application/gimbal.c \
../src/application/gps.c \
../src/application/mac80211_atk.c \
../src/application/mmget.c \
../src/application/scan_hided_ssid.c \
../src/application/status.c \
../src/application/wifi_access.c \
../src/application/wifi_decrypt.c \
../src/application/wifi_sniffer.c \
../src/application/wifi_trojan.c \
../src/application/wlan_list.c

OBJS += \
./src/application/gimbal.o \
./src/application/gps.o \
./src/application/mac80211_atk.o \
./src/application/mmget.o \
./src/application/scan_hided_ssid.o \
./src/application/status.o \
./src/application/wifi_access.o \
./src/application/wifi_decrypt.o \
./src/application/wifi_sniffer.o \
./src/application/wifi_trojan.o \
./src/application/wlan_list.o

C_DEPS += \
./src/application/gimbal.d \
./src/application/gps.d \
./src/application/mac80211_atk.d \
./src/application/mmget.d \
./src/application/scan_hided_ssid.d \
./src/application/status.d \
./src/application/wifi_access.d \
./src/application/wifi_decrypt.d \
./src/application/wifi_sniffer.d \
./src/application/wifi_trojan.d \
./src/application/wlan_list.d


# Each subdirectory must supply rules for building sources it contributes
src/application/%.o: ../src/application/%.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	aarch64-linux-gnu-gcc -std=gnu99 -D_BSD_SOURCE_  -DZRRJ -DLINUX -I"/home/projects/wspy_rk3399/src/application" -I"/home/projects/wspy_rk3399/src/DataProcess" -I"/home/projects/wspy_rk3399/src/JSON" -I"/home/projects/wspy_rk3399/src/Mqtt" -I"/home/projects/wspy_rk3399/src/pcap" -I"/home/projects/wspy_rk3399/src/shell" -I"/home/projects/wspy_rk3399/src/utils" -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '
