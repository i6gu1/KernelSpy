package handlers

import "testing"

// TestOrderQueueCapacity verifies the order/queue system: the first 100
// uploads (orders) each reserve a slot, the 101st is rejected, and once a
// running scan finishes (slot released) the next order can take its place.
func TestOrderQueueCapacity(t *testing.T) {
	// Drain any slots left over from other tests so this test is hermetic.
	for len(orderSlots) > 0 {
		releaseOrderSlot()
	}

	const capacity = 100
	// Fill all 100 slots.
	for i := 0; i < capacity; i++ {
		if !reserveOrderSlot() {
			t.Fatalf("order %d should have reserved a slot", i+1)
		}
	}

	// Order 101 must be rejected while all 100 are running.
	if reserveOrderSlot() {
		t.Fatal("101st order should have been rejected while all 100 slots are busy")
	}

	// When one scan finishes, its slot frees up and the next order proceeds.
	releaseOrderSlot()
	if !reserveOrderSlot() {
		t.Fatal("a slot should have opened after one scan finished")
	}

	// Clean up: release everything this test reserved so other tests (and the
	// real server, if this runs in-process) start from a clean state.
	for len(orderSlots) > 0 {
		releaseOrderSlot()
	}
}
