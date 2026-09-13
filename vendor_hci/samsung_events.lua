-- Vendor subevent → body parser; the common adapter has consumed the subevent.
-- BluetoothKit 999c164: SamsungEventDispatch maps 0x63 to BtStatusDispatch.
return {
    [0x63] = require("samsung_events_bt_status")
}
