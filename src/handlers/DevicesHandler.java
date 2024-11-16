package handlers;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import entities.Device;

public class DevicesHandler {

    private ArrayList<Device> devices;
    private File devicesFile;
    private static DevicesHandler instance;
    private SecurityHandler sh;

    public DevicesHandler(SecurityHandler security)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, ClassNotFoundException {
        this.devices = new ArrayList<>();
        File txtFolder = new File("txtFiles");
        this.devicesFile = new File("txtFiles//devices.txt");
        this.sh = security;
        try {
            if (!txtFolder.exists()) {
                txtFolder.mkdir();

            }
            if (!devicesFile.exists() || devicesFile.length() == 0) {

                devicesFile.createNewFile();
            } else {
                String data;
                if (!(data = sh.verifyIntegrity(devicesFile.getPath())).equals("nValid")) {

                    getDevicesByTextFile(data);
                } else {
                    devicesFile.delete();
                    devicesFile.createNewFile();
                }

            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
    }

    public static DevicesHandler getInstance(SecurityHandler security)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException, ClassNotFoundException {
        if (instance == null) {
            instance = new DevicesHandler(security);
        }

        return instance;
    }

    private void getDevicesByTextFile(String data) {
        try {
            Scanner sc = new Scanner(data);
            while (sc.hasNext()) {
                String[] line = sc.nextLine().split(":");
                Device device = null;
                if (line.length == 4) {
                    device = new Device(line[0], Integer.parseInt(line[1]));
                    device.update_temp(Float.parseFloat(line[2]));
                    device.update_file(new File(line[3]));
                } else if (line.length == 3) {
                    device = new Device(line[0], Integer.parseInt(line[1]));
                    try {
                        device.update_temp(Float.parseFloat(line[2]));
                    } catch (NumberFormatException e) {
                        device.update_file(new File(line[2]));
                    }
                } else {
                    device = new Device(line[0], Integer.parseInt(line[1]));
                }
                devices.add(device);
            }
            sc.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean device_used(int deviceId, String user) {
        Device device = null;
        if ((device = get_device(deviceId, user)) != null) {
            return device.isUsed();
        }

        return false;
    }

    public void update_device_file(int deviceId, File image, String user) {
        for (Device device : devices) {
            if (device.getId() == deviceId && device.getUser().equals(user)) {
                device.update_file(image);
            }
        }

    }

    public void update_device_to_used(int deviceId, String user) {
        for (Device device : devices) {
            if (device.getId() == deviceId && device.getUser().equals(user)) {
                device.update_state_to_used();
            }
        }
    }

    public void update_device_to_not_used(int deviceId, String user) {
        for (Device device : devices) {
            if (device.getId() == deviceId && device.getUser().equals(user)) {
                device.update_state_to_not_used();
            }
        }
    }

    private Device get_device(int deviceId, String user) {
        for (Device device : devices) {
            if (device.getId() == deviceId && device.getUser().equals(user)) {
                return device;
            }
        }
        return null;
    }

    public void update_temp(int deviceId, float temp, String user) {
        for (Device device : devices) {
            if (device.getId() == deviceId && device.getUser().equals(user)) {
                device.update_temp(temp);
            }
        }
    }

    public void update_file() {
        StringBuilder output = new StringBuilder();
        try {
            for (Device device : devices) {
                output.append(device.getUser() + ":" + device.getId());
                if (device.getTemp() != 0) {
                    output.append(":" + device.getTemp());
                }
                if (device.getFile() != null) {
                    output.append(":" + "imgFilesServer//" + device.getFile().getName());
                }
                output.append("\n");
            }
            this.sh.writeHmacFile(output.toString(), this.devicesFile.getPath());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void create_device(String user_name, int deviceId) {
        devices.add(new Device(user_name, deviceId));
    }

    public File getTemp(List<String> devicesInDomain) throws IOException {
        File temp_file = new File("txtFiles//devicesTemp.txt");
        Writer w = new FileWriter("txtFiles//devicesTemp.txt");
        for (String device : devicesInDomain) {
            String[] user_deviceId = device.split(":");
            Device current_device = get_device(Integer.parseInt(user_deviceId[1]), user_deviceId[0]);
            if (current_device != null) {
                w.append("<" + device + ">" + " - " + current_device.getTemp() + "\n");
            }
        }
        w.close();
        return temp_file;
    }

    public boolean exist(String user_name, int deviceId) {
        return get_device(deviceId, user_name) != null;
    }

    public File getFile(String string, int int1) {
        File file = null;
        for (Device device : devices) {
            if (device.getUser().equals(string) && device.getId() == int1) {
                file = device.getFile();
            }
        }
        return file;
    }
}
