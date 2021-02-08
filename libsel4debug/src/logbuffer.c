/*
 * Copyright 2020, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the BSD 2-Clause license. Note that NO WARRANTY is provided.
 * See "LICENSE_BSD2.txt" for details.
 *
 * @TAG(DATA61_BSD)
 */

/* Utilities for working with the debug log buffer */

#include <autoconf.h>
#include <sel4debug/logbuffer.h>
#include <utils/base64.h>
#include <utils/cbor64.h>

/* Strings tracked and compressed in the string domain */
char *identifiers[] = {
    /* Event type */
    "type",
    "Unknown",

    /* None event */
    "None",

    /* Entry and exit events */
    "Entry",
    "Exit",
    "cpu-id",
    "timestamp",

    /* Block event */
    "Block",
    "reason",
    "Receive",
    "Send",
    "Reply",
    "Notification",
    "object",

    /* Resume and switch events */
    "Resume",
    "Postpone",
    "SwitchThread",
    "SwitchSchedContext",
    "thread",
    "release",
    "sched-context",

    /* Timestamp event */
    "Timestamp",
    "microseconds",
    "cycles",

    /* NULL array terminator */
    NULL,
};

#if CONFIG_MAX_NUM_NODES > 0
#define SMP_ENABLED
#define SMP_COND(_t, _f) (_t)
#else
#define SMP_COND(_t, _f) (_f)
#endif

/* Number of fields in event other than the type fields */
size_t field_count[seL4_NumLogTypeIds] = {
    [seL4_Log_TypeId(None)] = 0,
    [seL4_Log_TypeId(Entry)] = SMP_COND(2, 1),
    [seL4_Log_TypeId(Exit)] = SMP_COND(2, 1),
    [seL4_Log_TypeId(Block)] = 2,
    [seL4_Log_TypeId(Resume)] = 1,
    [seL4_Log_TypeId(Postpone)] = 1,
    [seL4_Log_TypeId(SwitchThread)] = SMP_COND(2, 1),
    [seL4_Log_TypeId(SwitchSchedContext)] = SMP_COND(2, 1),
    [seL4_Log_TypeId(Timestamp)] = SMP_COND(3, 2),
};

/*
 * Dump a single event as JSON
 */
static int event_cbor64(seL4_LogEvent *event, cbor64_domain_t *domain, base64_t *streamer)
{
    int event_type = seL4_LogEvent_type(event);

    /* Display the type */
    cbor64_map_length(streamer, field_count[event_type] + 1);
    cbor64_utf8_ref(streamer, domain, "type");

    switch (event_type) {
    case seL4_Log_TypeId(None): {
        cbor64_utf8_ref(streamer, domain, "None");
        break;
    }

    case seL4_Log_TypeId(Entry): {
        seL4_Log_Type(Entry) *entry = seL4_Log_Cast(Entry)event;
        cbor64_utf8_ref(streamer, domain, "Entry");

#ifdef SMP_ENABLED
        cbor64_utf8_ref(streamer, domain, "cpu-id");
        cbor64_uint(streamer, event->data);
#endif

        cbor64_utf8_ref(streamer, domain, "timestamp");
        cbor64_uint(streamer, entry->timestamp);
        break;
    }

    case seL4_Log_TypeId(Exit): {
        seL4_Log_Type(Exit) *exit = seL4_Log_Cast(Exit)event;
        cbor64_utf8_ref(streamer, domain, "Exit");

#ifdef SMP_ENABLED
        cbor64_utf8_ref(streamer, domain, "cpu-id");
        cbor64_uint(streamer, event->data);
#endif

        cbor64_utf8_ref(streamer, domain, "timestamp");
        cbor64_uint(streamer, exit->timestamp);
        break;
    }

    case seL4_Log_TypeId(Block): {
        seL4_Log_Type(Block) *block = seL4_Log_Cast(Block)event;
        cbor64_utf8_ref(streamer, domain, "Block");

        cbor64_utf8_ref(streamer, domain, "reason");
        switch (event->data) {
        case seL4_Log_Block_EndpointRecieve:
            cbor64_utf8_ref(streamer, domain, "Receive");
            break;

        case seL4_Log_Block_EndpointSend:
            cbor64_utf8_ref(streamer, domain, "Send");
            break;

        case seL4_Log_Block_Reply:
            cbor64_utf8_ref(streamer, domain, "Reply");
            break;

        case seL4_Log_Block_NotificationRecieve:
            cbor64_utf8_ref(streamer, domain, "Notification");
            break;

        default:
            cbor64_uint(streamer, event->data);
            break;
        }

        cbor64_utf8_ref(streamer, domain, "object");
        cbor64_uint(streamer, block->object);
        break;
    }

    case seL4_Log_TypeId(Resume): {
        seL4_Log_Type(Resume) *resume = seL4_Log_Cast(Resume)event;
        cbor64_utf8_ref(streamer, domain, "Resume");

        cbor64_utf8_ref(streamer, domain, "thread");
        cbor64_uint(streamer, resume->thread);
        break;
    }

    case seL4_Log_TypeId(Postpone): {
        seL4_Log_Type(Postpone) *postpone = seL4_Log_Cast(Postpone)event;
        cbor64_utf8_ref(streamer, domain, "Postpone");

        cbor64_utf8_ref(streamer, domain, "release");
        cbor64_uint(streamer, postpone->release);
        break;
    }

    case seL4_Log_TypeId(SwitchThread): {
        seL4_Log_Type(SwitchThread) *switch_thread =
            seL4_Log_Cast(SwitchThread)event;
        cbor64_utf8_ref(streamer, domain, "SwitchThread");

#ifdef SMP_ENABLED
        cbor64_utf8_ref(streamer, domain, "cpu-id");
        cbor64_uint(streamer, event->data);
#endif

        cbor64_utf8_ref(streamer, domain, "thread");
        cbor64_uint(streamer, switch_thread->thread);
        break;
    }

    case seL4_Log_TypeId(SwitchSchedContext): {
        seL4_Log_Type(SwitchSchedContext) *switch_sc =
            seL4_Log_Cast(SwitchSchedContext)event;
        cbor64_utf8_ref(streamer, domain, "SwitchSchedContext");

#ifdef SMP_ENABLED
        cbor64_utf8_ref(streamer, domain, "cpu-id");
        cbor64_uint(streamer, event->data);
#endif

        cbor64_utf8_ref(streamer, domain, "sched-context");
        cbor64_uint(streamer, switch_sc->sched_context);
        break;
    }

    case seL4_Log_TypeId(Timestamp): {
        seL4_Log_Type(Timestamp) *timestamp =
            seL4_Log_Cast(Timestamp)event;
        cbor64_utf8_ref(streamer, domain, "Timestamp");

#ifdef SMP_ENABLED
        cbor64_utf8_ref(streamer, domain, "cpu-id");
        cbor64_uint(streamer, event->data);
#endif

        cbor64_utf8_ref(streamer, domain, "microseconds");
        cbor64_uint(streamer, timestamp->microseconds);

        cbor64_utf8_ref(streamer, domain, "cycles");
        cbor64_uint(streamer, timestamp->cycles);
        break;
    }

    default: {
        cbor64_utf8_ref(streamer, domain, "Unknown");
        break;
    }
    }

    return 0;
}

/*
 * Dump the debug log to the given output
 */
int debug_log_buffer_dump_cbor64(seL4_LogBuffer *buffer, base64_t *streamer)
{
    /* Start a new string domain */
    cbor64_domain_t domain;
    cbor64_string_ref_domain(streamer, identifiers, &domain);

    /* Stop logging events */
    debug_log_buffer_finalise(buffer);

    /* Create a copy of the log buffer to traverse the events */
    seL4_LogBuffer cursor = *buffer;

    cbor64_array_start(streamer);
    seL4_LogEvent *event = seL4_LogBuffer_next(&cursor);
    while (event != NULL) {
        int err = event_cbor64(event, &domain, streamer);
        if (err != 0) {
            return err;
        }

        event = seL4_LogBuffer_next(&cursor);
    }
    return cbor64_array_end(streamer);
}
