from delta2.generators.delta_pid import (xls2stx_winlol, xls2stx_htool, xls2stx_pview)
from delta2.generators.delta_eid import (xls2stx_ransom_process_create, xls2stx_ransom_process_access,
                                         xls2stx_ransom_file, xls2stx_ransom_generic)

from delta2.generators.delta_did.process_create import (process_create__any, process_create__windows_any,
                                                        process_create__linux_any, process_create__mac_any,
                                                        process_create_mde__any)

from delta2.generators.delta_did.file_events import (file_create__any, file_event_mde__any)

