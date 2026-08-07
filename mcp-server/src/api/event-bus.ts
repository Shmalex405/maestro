// Shared in-process event bus for assessment SSE.
//
// Extracted from routes/assessments.ts so non-routing code (the tool-dispatch
// chokepoint in server.ts / autonomous-runner.ts) can emit onto the same bus
// the SSE endpoint (`GET /api/assessments/:id/events`) relays from, without the
// dispatch path having to import the routes layer (which would be circular).
//
// Events are emitted on the channel `assessment:${id}` with the shape
// `{ type, data }`; the SSE route writes `event: ${type}\ndata: ${json}`.

import { EventEmitter } from "events";

export const assessmentEvents = new EventEmitter();
// Each connected SSE client and each emitter adds listeners; keep the ceiling
// high so concurrent assessments + the live Assessment View never warn.
assessmentEvents.setMaxListeners(200);
