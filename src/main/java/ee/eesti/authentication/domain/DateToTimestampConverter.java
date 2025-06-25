package ee.eesti.authentication.domain;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.util.Date;

/**
 * Serializer that allows serializing Date as a numerical timestamp.
 */
public class DateToTimestampConverter extends StdSerializer<Date> {

    public DateToTimestampConverter() {
        this(Date.class);
    }

    protected DateToTimestampConverter(Class<Date> t) {
        super(t);
    }

    /**
     * Serializes Date value as numerical timestamp.
     *
     * @param value  Date to be serialized
     * @param gen json generator - provides public api for writing json
     * @param provider  defines public api to obtain suitable serializers for specific types (used by JsonSerializer)
     * @throws IOException
     */
    @Override
    public void serialize(Date value, JsonGenerator gen, SerializerProvider provider) throws IOException {
        if (value != null) {
            gen.writeNumber(value.getTime());
        } else {
            gen.writeNull();
        }
    }
}
