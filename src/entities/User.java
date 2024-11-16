package entities;

import java.util.ArrayList;
import java.util.List;

public class User {
    private String name;
    private String cert_path;
    private List<Integer> devices;

    public User(String name, String cert_path) {
        this.name = name;
        this.cert_path = cert_path;
        this.devices = new ArrayList<>();
    }

    public String getName() {
        return this.name;
    }

    public String getCert() {
        return this.cert_path;
    }

    public List<Integer> get_devices() {
        return this.devices;
    }

    public void add_device(int deviceId) {
        this.devices.add(deviceId);
    }

}
