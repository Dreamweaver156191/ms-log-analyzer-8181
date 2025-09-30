package za.co.frei.logfile.analyzer.model;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class EventTypeTest {

    @Test
    public void shouldHaveAllRequiredEventTypes() {
        EventType[] events = EventType.values();
        assertEquals(5, events.length);

        assertTrue(containsEvent(events, EventType.LOGIN_SUCCESS));
        assertTrue(containsEvent(events, EventType.LOGIN_FAILURE));
        assertTrue(containsEvent(events, EventType.FILE_UPLOAD));
        assertTrue(containsEvent(events, EventType.FILE_DOWNLOAD));
        assertTrue(containsEvent(events, EventType.LOGOUT));
    }

    @Test
    public void shouldConvertFromString() {
        assertEquals(EventType.LOGIN_SUCCESS, EventType.valueOf("LOGIN_SUCCESS"));
        assertEquals(EventType.LOGIN_FAILURE, EventType.valueOf("LOGIN_FAILURE"));
        assertEquals(EventType.FILE_UPLOAD, EventType.valueOf("FILE_UPLOAD"));
        assertEquals(EventType.FILE_DOWNLOAD, EventType.valueOf("FILE_DOWNLOAD"));
        assertEquals(EventType.LOGOUT, EventType.valueOf("LOGOUT"));
    }

    @Test
    public void shouldThrowExceptionForInvalidEventType() {
        assertThrows(IllegalArgumentException.class, () -> {
            EventType.valueOf("INVALID_EVENT");
        });
    }

    private boolean containsEvent(EventType[] events, EventType target) {
        for (EventType event : events) {
            if (event == target) {
                return true;
            }
        }
        return false;
    }
}