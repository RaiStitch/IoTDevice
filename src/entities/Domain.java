package entities;

import java.util.ArrayList;
import java.util.List;

public class Domain {

    private String name;
    private String owner;
    private List<String> devices;
    private List<String> users;

    public Domain(String dominioID, String creatorID) {
        this.name = dominioID;
        this.owner = creatorID;
        this.devices = new ArrayList<>();
        this.users = new ArrayList<>();
    }

    public String getName() {
        return this.name;

    }

    public String getOwner() {
        return this.owner;
    }

    public List<String> getDevices() {
        return this.devices;
    }

    public List<String> getUsers() {
        return this.users;
    }

    public boolean contains_user(String user) {
        return this.users.contains(user);
    }

    public void addDevice(String device) {
        if(!this.devices.contains(device))
            this.devices.add(device);
    }

    public void addUser(String userToAdd) {
        if(!this.users.contains(userToAdd))
            this.users.add(userToAdd);
    }

    public boolean isOwner(String user) {
        return this.owner.equals(user);
    }

    public boolean contains_device(String device) {
        return this.devices.contains(device);
    }

}
