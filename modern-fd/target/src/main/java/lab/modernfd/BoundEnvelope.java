package lab.modernfd;

import java.util.List;

/** The final, fixed binding type used by the vulnerable endpoint. */
public final class BoundEnvelope {
    private List<Object> value;

    public BoundEnvelope() {
    }

    public List<Object> getValue() {
        return value;
    }

    public void setValue(List<Object> value) {
        this.value = value;
    }
}
