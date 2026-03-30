from queue import Queue
from typing import Any, Dict, Optional

from collector.base import BaseCollector, enrich_event, should_skip_event

_QUERY_PATH = "/audit-events/queries/events/v1"
_ENTITY_PATH = "/audit-events/entities/events/v1"
_EVENT_ID_FIELD = "id"
_TS_FIELD = "created_timestamp"


class AuditEventsCollector(BaseCollector):
    def __init__(
        self,
        api_client: Any,
        state_manager: Any,
        output_queue: Queue,
        config: Dict[str, Any],
        global_config: Dict[str, Any],
    ) -> None:
        super().__init__(
            source_name="audit_events",
            api_client=api_client,
            state_manager=state_manager,
            output_queue=output_queue,
            config=config,
            global_config=global_config,
        )

    def _poll(self) -> None:
        state = self._get_state()
        last_ts = state["last_timestamp"]
        last_id = state["last_id"]
        new_last_ts, new_last_id = last_ts, last_id
        after: Optional[str] = None

        while True:
            params: Dict[str, Any] = {
                "filter": f"created_timestamp:>='{last_ts}'",
                "sort": "created_timestamp.asc",
                "limit": self._batch_size,
            }
            if after:
                params["after"] = after

            query_resp = self._api.get(_QUERY_PATH, params=params)
            ids = query_resp.get("resources") or []

            if ids:
                entity_resp = self._api.get(_ENTITY_PATH, params={"ids": ids})
                events = entity_resp.get("resources") or []
                for event in events:
                    event_ts = event.get(_TS_FIELD, "")
                    event_id = event.get(_EVENT_ID_FIELD, "")
                    if should_skip_event(event_ts, event_id, last_ts, last_id):
                        continue
                    self._enqueue(enrich_event(event, "audit_events", self._tag, _EVENT_ID_FIELD))
                    if event_ts > new_last_ts or (event_ts == new_last_ts and event_id > new_last_id):
                        new_last_ts, new_last_id = event_ts, event_id
                if self._checkpoint_per_page:
                    self._save_state(new_last_ts, new_last_id)

            after = ((query_resp.get("meta") or {}).get("pagination") or {}).get("after")
            if not after:
                break

        self._save_state(new_last_ts, new_last_id)
