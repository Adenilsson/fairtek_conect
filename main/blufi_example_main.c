/*
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/


/****************************************************************************
* This is a demo for bluetooth config wifi connection to ap. You can config ESP32 to connect a softap
* or config ESP32 as a softap to be connected by other device. APP can be downloaded from github
* android source code: https://github.com/EspressifApp/EspBlufi
* iOS source code: https://github.com/EspressifApp/EspBlufiForiOS
****************************************************************************/

#include <stdio.h>//8
#include <stdlib.h>//8
#include <string.h>//8
#include "freertos/FreeRTOS.h"//8
#include "freertos/task.h"//8
#include "freertos/event_groups.h"//8
#include "esp_system.h"//8
#include "esp_wifi.h"//8
#include "esp_event.h"//8
#include "esp_log.h"//8
#include "nvs_flash.h"//8
#include "esp_bt.h"//8
#include "esp_eth.h"
#include "esp_event_loop.h"
#include "esp_blufi_api.h"
#include "blufi_example.h"
#include "netif/wlanif.h"
#include "esp_private/wifi.h"
#include "esp_blufi.h"

static void example_event_callback(esp_blufi_cb_event_t event, esp_blufi_cb_param_t *param);

#define WIFI_LIST_NUM   10
static const char* TAG = "eth2wifi_demo";

#define FLOW_CONTROL_QUEUE_TIMEOUT_MS (100)
#define FLOW_CONTROL_QUEUE_LENGTH (40)
#define FLOW_CONTROL_WIFI_SEND_TIMEOUT_MS (100)

typedef struct {
    void* packet;
    uint16_t length;
} flow_control_msg_t;

static bool mac_is_set = false;
static xQueueHandle eth_queue_handle;
//static bool gl_sta_connected = false;
static bool ethernet_is_connected = false;
static uint8_t eth_mac[6];
static esp_eth_handle_t s_eth_handle = NULL;
char teste[6];
uint8_t text[12];
static wifi_config_t sta_config;
static wifi_config_t ap_config;
uint8_t mac[6];
/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;

/* store the station info for send back to phone */
static bool gl_sta_connected = false;
static bool ble_is_connected = false;
static uint8_t gl_sta_bssid[6];
static uint8_t gl_sta_ssid[32];
static int gl_sta_ssid_len;



static void ethernet2wifi_mac_status_set(bool status)
{
    mac_is_set = status;
}

static bool ethernet2wifi_mac_status_get(void)
{
    return mac_is_set;
}
static esp_err_t pkt_eth2wifi(esp_eth_handle_t handle, uint8_t* buffer, uint32_t len)
{
    esp_err_t ret = ESP_OK;
    flow_control_msg_t msg = {
        .packet = buffer,
        .length = len,
    };

    if (xQueueSend(eth_queue_handle, &msg, pdMS_TO_TICKS(FLOW_CONTROL_QUEUE_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "Send flow control message failed or timeout");
        free(buffer);
        ret = ESP_FAIL;
    }

    return ret;
}

//======================================================================================
unsigned char FromHex(char c)
   {
   switch(c)
      {
      case '0': return 0;
      case '1': return 1;
      case '2': return 2;
      case '3': return 3;
      case '4': return 4;
      case '5': return 5;
      case '6': return 6;
      case '7': return 7;
      case '8': return 8;
      case '9': return 9;
      case 'a': return 10;
      case 'b': return 11;
      case 'c': return 12;
      case 'd': return 13;
      case 'e': return 14;
      case 'f': return 15;
      }
   // Report a problem here!

   return -1;
   }



//====================================================================================


static void eth_task(void* pvParameter)
{
    flow_control_msg_t msg;
    int res = 0;
    uint32_t timeout = 0;
    for (;;) {
        if (xQueueReceive(eth_queue_handle, &msg, (portTickType)portMAX_DELAY) == pdTRUE) {
            timeout = 0;
            if (msg.length) {
                do {
                    if (!ethernet2wifi_mac_status_get()) {
                        memcpy(eth_mac, (uint8_t*)msg.packet + 6, sizeof(eth_mac));
                        ESP_ERROR_CHECK(esp_wifi_start());
                        int e=0;
                                for(int i =0; i< 12 ;i+=2){
                                	printf("%d, %d \n ",text[i],text[i+1]);
                                	eth_mac[e] &= (FromHex(text[i])<<4)| FromHex(text[i+1]);

                                	e++;

                        }
                        ESP_LOGE(TAG, "MAC -->" MACSTR, MAC2STR(eth_mac));
                        //strncpy((char *)eth_mac, (char *)text, 12);
//djames
//#ifdef CONFIG_ETH_TO_STATION_MODE

                        esp_wifi_set_mac(WIFI_IF_STA, eth_mac);
                        esp_wifi_connect();
//#else
//                        esp_wifi_set_mac(WIFI_IF_AP,eth_mac);
//#endif
                        ethernet2wifi_mac_status_set(true);
                    }
                    vTaskDelay(pdMS_TO_TICKS(timeout));
                    timeout += 2;
                    if (gl_sta_connected) {
//djames
//#ifdef CONFIG_ETH_TO_STATION_MODE

                    	esp_wifi_internal_tx(WIFI_IF_STA, msg.packet, msg.length);
//#else
 //                  res = wifi_send_pkt_freedom(ESP_IF_WIFI_AP, msg.packet, msg.length);
//#endif
                    }
                } while (res && timeout < FLOW_CONTROL_WIFI_SEND_TIMEOUT_MS);
                if (res != ESP_OK) {
                    ESP_LOGE(TAG, "WiFi send packet failed: %d", res);
                }
            }

            free(msg.packet);
        }
    }
    vTaskDelete(NULL);
}

static void initialise_ethernet(void)
{
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();

    /* Set the PHY address in the example configuration */
    phy_config.phy_addr = CONFIG_PHY_ADDRESS;
    phy_config.reset_gpio_num = CONFIG_PHY_POWER_PIN;

    mac_config.smi_mdc_gpio_num = CONFIG_PHY_SMI_MDC_PIN;
    mac_config.smi_mdio_gpio_num = CONFIG_PHY_SMI_MDIO_PIN;
    esp_eth_mac_t* mac = esp_eth_mac_new_esp32(&mac_config);
    assert(mac);

//djames
//#if CONFIG_PHY_IP101
//    esp_eth_phy_t* phy = esp_eth_phy_new_ip101(&phy_config);
//#elif CONFIG_PHY_LAN8720
    esp_eth_phy_t* phy = esp_eth_phy_new_lan8720(&phy_config);
//#elif CONFIG_PHY_RTL8201
//    esp_eth_phy_t* phy = esp_eth_phy_new_rtl8201(&phy_config);
//#elif CONFIG_PHY_DP83848
//    esp_eth_phy_t* phy = esp_eth_phy_new_dp83848(&phy_config);
//#endif
    assert(phy);

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    config.stack_input = pkt_eth2wifi;
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &s_eth_handle));
    esp_eth_ioctl(s_eth_handle, ETH_CMD_S_PROMISCUOUS, (void*)true);
    ESP_ERROR_CHECK(esp_eth_start(s_eth_handle));
}

static esp_err_t tcpip_adapter_sta_input_eth_output(void* buffer, uint16_t len, void* eb)
{
    if (ethernet_is_connected) {
        if (esp_eth_transmit(s_eth_handle, buffer, len) != ESP_OK) {
            ESP_LOGE(TAG, "Ethernet send packet failed");
        }else{
        	ESP_LOGE(TAG, "MAC" MACSTR, MAC2STR(eth_mac));



        }
        //ESP_LOG_BUFFER_HEX("output", buffer,len);
    }

    esp_wifi_internal_free_rx_buffer(eb);
    return ESP_OK;
}

static esp_err_t tcpip_adapter_ap_input_eth_output(void* buffer, uint16_t len, void* eb)
{
    if (ethernet_is_connected) {
        if (esp_eth_transmit(s_eth_handle, buffer, len) != ESP_OK) {
            ESP_LOGE(TAG, "Ethernet send packet failed");
        }
    }

    esp_wifi_internal_free_rx_buffer(eb);
    return ESP_OK;
}










static void ip_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    wifi_mode_t mode;

    switch (event_id) {
    case IP_EVENT_STA_GOT_IP: {
    	 ESP_LOGE(TAG, "EVENT_STA_GOT_IP");
        esp_blufi_extra_info_t info;

        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        esp_wifi_get_mode(&mode);
        memset(&info, 0, sizeof(esp_blufi_extra_info_t));
        memcpy(info.sta_bssid, gl_sta_bssid, 6);
        info.sta_bssid_set = true;
        info.sta_ssid = gl_sta_ssid;
        info.sta_ssid_len = gl_sta_ssid_len;
        if (ble_is_connected == true) {
            esp_blufi_send_wifi_conn_report(mode, ESP_BLUFI_STA_CONN_SUCCESS, 0, &info);
            esp_wifi_internal_reg_rxcb(WIFI_IF_STA, (wifi_rxcb_t)tcpip_adapter_sta_input_eth_output);
        } else {
            BLUFI_INFO("BLUFI BLE is not connected yet\n");
            esp_wifi_internal_reg_rxcb(WIFI_IF_STA, (wifi_rxcb_t)tcpip_adapter_sta_input_eth_output);
        }

        break;
    }
    default:
        break;
    }
    return;
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    wifi_event_sta_connected_t *event;
    wifi_mode_t mode;

    switch (event_id) {
    case WIFI_EVENT_STA_START:
        //esp_wifi_connect();
    	ESP_LOGE(TAG, "WIFI_EVENT_STA_START");
        break;
    case WIFI_EVENT_STA_CONNECTED:
    	ESP_LOGE(TAG, "WIFI_EVENT_STA_CONNECTED");
        gl_sta_connected = true;
        event = (wifi_event_sta_connected_t*) event_data;
        memcpy(gl_sta_bssid, event->bssid, 6);
        memcpy(gl_sta_ssid, event->ssid, event->ssid_len);
        gl_sta_ssid_len = event->ssid_len;
        esp_wifi_internal_reg_rxcb(WIFI_IF_STA, (wifi_rxcb_t)tcpip_adapter_sta_input_eth_output);
        break;
    case WIFI_EVENT_STA_DISCONNECTED:
    	ESP_LOGE(TAG, "WIFI_EVENT_STA_DISCONNECTED");
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        gl_sta_connected = false;
        memset(gl_sta_ssid, 0, 32);
        memset(gl_sta_bssid, 0, 6);
        gl_sta_ssid_len = 0;
        esp_wifi_internal_reg_rxcb(WIFI_IF_STA, NULL);
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    case WIFI_EVENT_AP_START:
        esp_wifi_get_mode(&mode);

        /* TODO: get config or information of softap, then set to report extra_info */
        if (ble_is_connected == true) {
            if (gl_sta_connected) {
                esp_blufi_send_wifi_conn_report(mode, ESP_BLUFI_STA_CONN_SUCCESS, 0, NULL);
            } else {
                esp_blufi_send_wifi_conn_report(mode, ESP_BLUFI_STA_CONN_FAIL, 0, NULL);
            }
        } else {
            BLUFI_INFO("BLUFI BLE is not connected yet\n");
        }
        break;
    case WIFI_EVENT_SCAN_DONE: {
        uint16_t apCount = 0;
        esp_wifi_scan_get_ap_num(&apCount);
        if (apCount == 0) {
            BLUFI_INFO("Nothing AP found");
            break;
        }
        wifi_ap_record_t *ap_list = (wifi_ap_record_t *)malloc(sizeof(wifi_ap_record_t) * apCount);
        if (!ap_list) {
            BLUFI_ERROR("malloc error, ap_list is NULL");
            break;
        }
        ESP_ERROR_CHECK(esp_wifi_scan_get_ap_records(&apCount, ap_list));
        esp_blufi_ap_record_t * blufi_ap_list = (esp_blufi_ap_record_t *)malloc(apCount * sizeof(esp_blufi_ap_record_t));
        if (!blufi_ap_list) {
            if (ap_list) {
                free(ap_list);
            }
            BLUFI_ERROR("malloc error, blufi_ap_list is NULL");
            break;
        }
        for (int i = 0; i < apCount; ++i)
        {
            blufi_ap_list[i].rssi = ap_list[i].rssi;
            memcpy(blufi_ap_list[i].ssid, ap_list[i].ssid, sizeof(ap_list[i].ssid));
        }

        if (ble_is_connected == true) {
            esp_blufi_send_wifi_list(apCount, blufi_ap_list);
        } else {
            BLUFI_INFO("BLUFI BLE is not connected yet\n");
        }

        esp_wifi_scan_stop();
        free(ap_list);
        free(blufi_ap_list);
        break;
    }
    default:
        break;
    }
    return;
}
static void eth_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data){
	printf("ETH_EVVENT_HANDLER LINH 331 \n");
	switch (event_id) {
	        case ETHERNET_EVENT_CONNECTED:
	            printf("ETHERNET_EVENT_CONNECTED\n");
	            ethernet_is_connected = true;
	            esp_eth_ioctl(s_eth_handle, ETH_CMD_G_MAC_ADDR, eth_mac);
	            //#ifdef CONFIG_ETH_TO_STATION_MODE
	            esp_wifi_set_mac(WIFI_IF_STA, eth_mac);
	            //ESP_LOGI(TAG, "mac: " MACSTR, MAC2STR(eth_mac));
	            //#else
	            //            esp_wifi_set_mac(WIFI_IF_AP, eth_mac);
	            //#endif
	            //            ESP_ERROR_CHECK(esp_wifi_start());
	            //#ifdef CONFIG_ETH_TO_STATION_MODE
	            // ESP_ERROR_CHECK(esp_wifi_connect());
	            //#endif
	            break;
	        case ETHERNET_EVENT_DISCONNECTED:
	            printf("ETHERNET_EVENT_DISCONNECTED\n");
	            ethernet2wifi_mac_status_set(false);
	            ethernet_is_connected = false;
	            ESP_ERROR_CHECK(esp_wifi_stop());
	            break;
	        default:
	            break;
	        }
}
static void initialise_wifi(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    wifi_event_group = xEventGroupCreate();

    esp_netif_t *sta_netif = esp_netif_create_default_wifi_sta();

    	 assert(sta_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

static esp_blufi_callbacks_t example_callbacks = {
    .event_cb = example_event_callback,
    .negotiate_data_handler = blufi_dh_negotiate_data_handler,
    .encrypt_func = blufi_aes_encrypt,
    .decrypt_func = blufi_aes_decrypt,
    .checksum_func = blufi_crc_checksum,
};


static void example_event_callback(esp_blufi_cb_event_t event, esp_blufi_cb_param_t *param)
{
    /* actually, should post to blufi_task handle the procedure,
     * now, as a example, we do it more simply */

    switch (event) {
    case ESP_BLUFI_EVENT_INIT_FINISH:
        BLUFI_INFO("BLUFI init finish\n");

        esp_blufi_adv_start();
        break;
    case ESP_BLUFI_EVENT_DEINIT_FINISH:
        BLUFI_INFO("BLUFI deinit finish\n");
        break;
    case ESP_BLUFI_EVENT_BLE_CONNECT:
        BLUFI_INFO("BLUFI ble connect\n");
        ble_is_connected = true;
        esp_blufi_adv_stop();
        blufi_security_init();
        break;
    case ESP_BLUFI_EVENT_BLE_DISCONNECT:
        BLUFI_INFO("BLUFI ble disconnect\n");
        ble_is_connected = false;
        blufi_security_deinit();
        esp_blufi_adv_start();
        break;
    case ESP_BLUFI_EVENT_SET_WIFI_OPMODE:
        BLUFI_INFO("BLUFI Set WIFI opmode %d\n", param->wifi_mode.op_mode);
        ESP_ERROR_CHECK( esp_wifi_set_mode(param->wifi_mode.op_mode) );
        break;
    case ESP_BLUFI_EVENT_REQ_CONNECT_TO_AP:
        BLUFI_INFO("BLUFI requset wifi connect to AP\n");
        /* there is no wifi callback when the device has already connected to this wifi
        so disconnect wifi before connection.
        */
        esp_wifi_disconnect();
        esp_wifi_connect();
        break;
    case ESP_BLUFI_EVENT_REQ_DISCONNECT_FROM_AP:
        BLUFI_INFO("BLUFI requset wifi disconnect from AP\n");
        esp_wifi_disconnect();
        break;
    case ESP_BLUFI_EVENT_REPORT_ERROR:
        BLUFI_ERROR("BLUFI report error, error code %d\n", param->report_error.state);
        esp_blufi_send_error_info(param->report_error.state);
        break;
    case ESP_BLUFI_EVENT_GET_WIFI_STATUS: {
        wifi_mode_t mode;
        esp_blufi_extra_info_t info;

        esp_wifi_get_mode(&mode);

        if (gl_sta_connected) {
            memset(&info, 0, sizeof(esp_blufi_extra_info_t));
            memcpy(info.sta_bssid, gl_sta_bssid, 6);
            info.sta_bssid_set = true;
            info.sta_ssid = gl_sta_ssid;
            info.sta_ssid_len = gl_sta_ssid_len;
            esp_blufi_send_wifi_conn_report(mode, ESP_BLUFI_STA_CONN_SUCCESS, 0, &info);
        } else {
            esp_blufi_send_wifi_conn_report(mode, ESP_BLUFI_STA_CONN_FAIL, 0, NULL);
        }
        BLUFI_INFO("BLUFI get wifi status from AP\n");

        break;
    }
    case ESP_BLUFI_EVENT_RECV_SLAVE_DISCONNECT_BLE:
        BLUFI_INFO("blufi close a gatt connection");
        esp_blufi_disconnect();
        break;
    case ESP_BLUFI_EVENT_DEAUTHENTICATE_STA:
        /* TODO */
        break;
	case ESP_BLUFI_EVENT_RECV_STA_BSSID:
        memcpy(sta_config.sta.bssid, param->sta_bssid.bssid, 6);
        sta_config.sta.bssid_set = 1;
        esp_wifi_set_config(WIFI_IF_STA, &sta_config);
        BLUFI_INFO("Recv STA BSSID %s\n", sta_config.sta.ssid);
        break;
	case ESP_BLUFI_EVENT_RECV_STA_SSID:
        strncpy((char *)sta_config.sta.ssid, (char *)param->sta_ssid.ssid, param->sta_ssid.ssid_len);
        sta_config.sta.ssid[param->sta_ssid.ssid_len] = '\0';
        esp_wifi_set_config(WIFI_IF_STA, &sta_config);
        BLUFI_INFO("Recv STA SSID %s\n", sta_config.sta.ssid);
        break;
	case ESP_BLUFI_EVENT_RECV_STA_PASSWD:
        strncpy((char *)sta_config.sta.password, (char *)param->sta_passwd.passwd, param->sta_passwd.passwd_len);
        sta_config.sta.password[param->sta_passwd.passwd_len] = '\0';
        esp_wifi_set_config(WIFI_IF_STA, &sta_config);
        BLUFI_INFO("Recv STA PASSWORD %s\n", sta_config.sta.password);
        break;
	case ESP_BLUFI_EVENT_RECV_SOFTAP_SSID:
        strncpy((char *)ap_config.ap.ssid, (char *)param->softap_ssid.ssid, param->softap_ssid.ssid_len);
        ap_config.ap.ssid[param->softap_ssid.ssid_len] = '\0';
        ap_config.ap.ssid_len = param->softap_ssid.ssid_len;
        esp_wifi_set_config(WIFI_IF_AP, &ap_config);
        BLUFI_INFO("Recv SOFTAP SSID %s, ssid len %d\n", ap_config.ap.ssid, ap_config.ap.ssid_len);
        break;
	case ESP_BLUFI_EVENT_RECV_SOFTAP_PASSWD:
        strncpy((char *)ap_config.ap.password, (char *)param->softap_passwd.passwd, param->softap_passwd.passwd_len);
        ap_config.ap.password[param->softap_passwd.passwd_len] = '\0';
        esp_wifi_set_config(WIFI_IF_AP, &ap_config);
        BLUFI_INFO("Recv SOFTAP PASSWORD %s len = %d\n", ap_config.ap.password, param->softap_passwd.passwd_len);
        break;
	case ESP_BLUFI_EVENT_RECV_SOFTAP_MAX_CONN_NUM:
        if (param->softap_max_conn_num.max_conn_num > 4) {
            return;
        }
        ap_config.ap.max_connection = param->softap_max_conn_num.max_conn_num;
        esp_wifi_set_config(WIFI_IF_AP, &ap_config);
        BLUFI_INFO("Recv SOFTAP MAX CONN NUM %d\n", ap_config.ap.max_connection);
        break;
	case ESP_BLUFI_EVENT_RECV_SOFTAP_AUTH_MODE:
        if (param->softap_auth_mode.auth_mode >= WIFI_AUTH_MAX) {
            return;
        }
        ap_config.ap.authmode = param->softap_auth_mode.auth_mode;
        esp_wifi_set_config(WIFI_IF_AP, &ap_config);
        BLUFI_INFO("Recv SOFTAP AUTH MODE %d\n", ap_config.ap.authmode);
        break;
	case ESP_BLUFI_EVENT_RECV_SOFTAP_CHANNEL:
        if (param->softap_channel.channel > 13) {
            return;
        }
        ap_config.ap.channel = param->softap_channel.channel;
        esp_wifi_set_config(WIFI_IF_AP, &ap_config);
        BLUFI_INFO("Recv SOFTAP CHANNEL %d\n", ap_config.ap.channel);
        break;
    case ESP_BLUFI_EVENT_GET_WIFI_LIST:{
        wifi_scan_config_t scanConf = {
            .ssid = NULL,
            .bssid = NULL,
            .channel = 0,
            .show_hidden = false
        };
        esp_wifi_scan_start(&scanConf, true);
        break;
    }
    case ESP_BLUFI_EVENT_RECV_CUSTOM_DATA:

        strncpy((char *)text, (char *)param->custom_data.data, param->custom_data.data_len);

        BLUFI_INFO("Recv Custom Data %d\n", param->custom_data.data_len);
        esp_log_buffer_hex("Custom Data",param->custom_data.data,param->custom_data.data_len);
        //ESP_LOGI(TAG, "Custom Data: %s", param->custom_data.data);
       // printf("String : %s \n", my_itoa(48, buf, 16));
        // ESP_LOGE(TAG, "MAC CORRIGIDO: " MACSTR, MAC2STR(eth_mac));
  //       sprintf(buf, "%s",param->custom_data.data);

        //ESP_LOGI(TAG,"Custom Data ==: %s",eth_mac);
        eth_queue_handle = xQueueCreate(FLOW_CONTROL_QUEUE_LENGTH, sizeof(flow_control_msg_t));
        xTaskCreate(eth_task, "eth_task", 2048, NULL, (tskIDLE_PRIORITY + 2), NULL);

        break;
	case ESP_BLUFI_EVENT_RECV_USERNAME:
        /* Not handle currently */
        break;
	case ESP_BLUFI_EVENT_RECV_CA_CERT:
        /* Not handle currently */
        break;
	case ESP_BLUFI_EVENT_RECV_CLIENT_CERT:
        /* Not handle currently */
        break;
	case ESP_BLUFI_EVENT_RECV_SERVER_CERT:
        /* Not handle currently */
        break;
	case ESP_BLUFI_EVENT_RECV_CLIENT_PRIV_KEY:
        /* Not handle currently */
        break;;
	case ESP_BLUFI_EVENT_RECV_SERVER_PRIV_KEY:
        /* Not handle currently */
        break;
    default:
        break;
    }
}

void app_main(void)
{
    esp_err_t ret;

    // Initialize NVS
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );
    tcpip_adapter_init();



    eth_queue_handle = xQueueCreate(FLOW_CONTROL_QUEUE_LENGTH, sizeof(flow_control_msg_t));
   // xTaskCreate(eth_task, "eth_task", 2048, NULL, (tskIDLE_PRIORITY + 2), NULL);

  //  ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(esp_event_loop_create_default());

    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, NULL));

    initialise_ethernet();
    initialise_wifi();

//    for(int i =30; i< 40; i++){
//    	printf((char)i);
//    	printf("\n");
//    }

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        BLUFI_ERROR("%s initialize bt controller failed: %s\n", __func__, esp_err_to_name(ret));
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret) {
        BLUFI_ERROR("%s enable bt controller failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }
    ret = esp_blufi_host_and_cb_init(&example_callbacks);
    if (ret) {
        BLUFI_ERROR("%s initialise failed: %s\n", __func__, esp_err_to_name(ret));
        return;
    }

    BLUFI_INFO("BLUFI VERSION %04x\n", esp_blufi_get_version());
}
