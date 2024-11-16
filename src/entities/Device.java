package entities;

import java.io.File;

public class Device {

    private int deviceID;
    private String user;
    private File file;
    private float temp;
    private boolean state;

    public Device(String user, int deviceID) {
        this.deviceID = deviceID;
        this.user = user;
        this.file = null;
        this.state = false;
        this.temp = 0;
    }

    public int getId() {
        return this.deviceID;
    }

    public boolean isUsed() {
        return this.state;
    }

    public void update_file(File image) {
        this.file = image;
    }

    public void update_state_to_used() {
        this.state = true;
    }

    public void update_state_to_not_used() {
        this.state = false;
    }

    public void update_temp(float temp) {
        this.temp = temp;
    }

    public String getUser() {
        return this.user;
    }

    public float getTemp() {
        return this.temp;
    }

    public File getFile() {
        return this.file;
    }

}
