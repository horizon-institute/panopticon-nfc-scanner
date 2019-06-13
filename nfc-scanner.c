#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>
#include <nfc/nfc-types.h>

#include <freefare.h>

#include <mosquitto.h>

#define _DEBUG_

#define MQTT_PORT 1883

#define NTAG21X_MAX_PAGES 45

#ifdef _DEBUG_
#define DEBUG(...)                 \
  do                               \
  {                                \
    printf("DEBUG: " __VA_ARGS__); \
    printf("\n");                  \
    fflush(stdout);                \
  } while (0)
#else
#define DEBUG(...) \
  {                \
  }
#endif

#ifdef _DEBUG_
#define WARN(...)                 \
  do                              \
  {                               \
    printf("WARN: " __VA_ARGS__); \
    printf("\n");                 \
    fflush(stdout);               \
  } while (0)
#else
#define WARN(...) \
  {               \
  }
#endif

#ifdef _DEBUG_
#define ERROR(...)                 \
  do                               \
  {                                \
    printf("ERROR: " __VA_ARGS__); \
    printf("\n");                  \
    fflush(stdout);                \
  } while (0)
#else
#define ERROR(...) \
  {                \
  }
#endif

static nfc_device *pnd = NULL;
static nfc_context *context;
static bool stopping = false;
static struct mosquitto* mqtt_client = NULL;

void target_present(const nfc_target *pnt, const char* topic)
{
  DEBUG("Target present");
  if (pnt->nm.nmt == NMT_ISO14443A) {
    FreefareTag tag = ntag21x_tag_new(pnd, *pnt);
    DEBUG("Tag type: %s", freefare_get_tag_friendly_name(tag));
    DEBUG("Tag UID: %s", freefare_get_tag_uid(tag));

    if (ntag21x_connect(tag) < 0)
    {
      ERROR("Could not connect to tag");
      ntag21x_tag_free(tag);
      return;
    }

    if (ntag21x_get_info(tag) < 0) {
      ERROR("Unable to get tag info");
      ntag21x_tag_free(tag);
      return;
    }

    uint8_t* buffer = malloc(NTAG21X_MAX_PAGES * 4);
    uint8_t page[4];
    for(uint8_t i = 4; i < NTAG21X_MAX_PAGES; i++)
    {
      if (ntag21x_read4(tag, i, page) < 0)
      {
        ERROR("Could not read tag page %i - %s", i, freefare_strerror(tag));
        free(buffer);
        ntag21x_tag_free(tag);
        return;
      }
      memcpy(buffer + ((i-4)*4), page, 4);
    }

    if (buffer[0] != 3) {
      DEBUG("Unknown tag format, skipping");
      free(buffer);
      ntag21x_tag_free(tag);
    }

    int counter = 1;
    DEBUG("Data size: %i", buffer[counter++]);
    DEBUG("Type: %i", buffer[2] & 0b00000111);
    uint8_t id_length_present = buffer[2] >> 3 & 0b00000001;
    counter++;
    DEBUG("ID length present: %i", id_length_present);
    DEBUG("Type length: %i", buffer[counter++]);
    uint8_t payload_length = buffer[counter++];
    DEBUG("Payload length: %i", payload_length);
    if (id_length_present)
    {
      DEBUG("ID length: %i", buffer[counter++]);
    }
    uint8_t record_type = buffer[counter++];
    DEBUG("Record type: %i", record_type);
    if (record_type != 'T')
    {
      DEBUG("Record is not a text type");
      free(buffer);
      ntag21x_tag_free(tag);
    }


    uint8_t* payload = calloc(payload_length, sizeof(uint8_t));
    memcpy(payload, buffer + counter + 1, payload_length - 1);
    if (strncmp("enpanopticon_", payload, 13) != 0)
    {
      DEBUG("Record is not a panopticon identifier");
      free(buffer);
      free(payload);
      ntag21x_tag_free(tag);
    }

    DEBUG("Payload: %s", payload);
    mosquitto_publish(mqtt_client, NULL, topic, payload_length - 1, payload, 1, false);

    free(buffer);
    free(payload);
    ntag21x_tag_free(tag);
  }
  else
  {
    DEBUG("Tag is not a Mifare Ultralight, ignoring");
  }
}

void target_removed(const char* topic)
{
  DEBUG("Target removed");
  mosquitto_publish(mqtt_client, NULL, topic, 7, "removed", 1, false);
}

static void stop(int signal)
{
  DEBUG("SIGINT received, stopping");
  stopping = true;
  if (pnd != NULL)
  {
    nfc_abort_command(pnd);
  }
  else
  {
    nfc_exit(context);
    mosquitto_destroy(mqtt_client);
    exit(EXIT_FAILURE);
  }
}

int main(int argc, const char **argv)
{
  if (argc != 3)
  {
    printf("Usage: nfc-poll <NFC device address> <device friendly name>\n");
    exit(EXIT_FAILURE);
  }

  signal(SIGINT, stop);

  mosquitto_lib_init();
  mqtt_client = mosquitto_new("nfc-scanner", false, NULL);
  mosquitto_connect(mqtt_client, "localhost", MQTT_PORT, 60);
  mosquitto_loop_start(mqtt_client);

  const uint8_t uiPollNr = 20;
  const uint8_t uiPeriod = 2;
  const nfc_modulation nmModulations[1] = {
      {.nmt = NMT_ISO14443A, .nbr = NBR_106},
      /*{.nmt = NMT_ISO14443B, .nbr = NBR_106},
      {.nmt = NMT_FELICA, .nbr = NBR_212},
      {.nmt = NMT_FELICA, .nbr = NBR_424},
      {.nmt = NMT_JEWEL, .nbr = NBR_106},*/
  };
  const size_t szModulations = 1;

  nfc_target nt;
  int res = 0;

  nfc_init(&context);
  if (context == NULL)
  {
    ERROR("Unable to init libnfc (malloc)");
    mosquitto_destroy(mqtt_client);
    exit(EXIT_FAILURE);
  }

  pnd = nfc_open(context, argv[1]);
  if (pnd == NULL)
  {
    ERROR("Unable to open NFC device %s", argv[1]);
    nfc_exit(context);
    mosquitto_destroy(mqtt_client);
    exit(EXIT_FAILURE);
  }

  if (nfc_initiator_init(pnd) < 0)
  {
    ERROR("Unable to initialise NFC device - %s", nfc_strerror(pnd));
    nfc_close(pnd);
    nfc_exit(context);
    mosquitto_destroy(mqtt_client);
    exit(EXIT_FAILURE);
  }

  DEBUG("%s/%s opened and initialised", argv[1], argv[2]);
  while (!stopping)
  {
    DEBUG("Polling for %ldms (%u cycles of %lums for %ld modulation[s])",
          (unsigned long) uiPollNr * szModulations * uiPeriod * 150,
          uiPollNr,
          (unsigned long) uiPeriod * 150,
          szModulations);
    if ((res = nfc_initiator_poll_target(
        pnd,nmModulations, szModulations, uiPollNr, uiPeriod, &nt)) < 0)
    {
      int ec = nfc_device_get_last_error(pnd);
      if (ec == NFC_ETIMEOUT || ec == NFC_EIO)
      {
        DEBUG("Polling timed out");
        continue;
      }
      ERROR("An error occurred during polling - %s", nfc_strerror(pnd));
      nfc_close(pnd);
      nfc_exit(context);
      mosquitto_destroy(mqtt_client);
      exit(EXIT_FAILURE);
    }

    if (res > 0)
    {
      target_present(&nt, argv[2]);
      DEBUG("Waiting for target removal");
      while (0 == nfc_initiator_target_is_present(pnd, &nt) && !stopping) { }
      if (nfc_device_get_last_error(pnd) != NFC_ETGRELEASED) {
        ERROR("An error occurred waiting for target removal - %s",
            nfc_strerror(pnd));
      }
      target_removed(argv[2]);
    }
    else
    {
      DEBUG("No target present");
    }
  }

  nfc_close(pnd);
  nfc_exit(context);
  mosquitto_destroy(mqtt_client);
  exit(EXIT_SUCCESS);
}
