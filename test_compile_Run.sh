mkdir -p ./build/classes
javac -cp "./libs/jason-3.3.0.jar" -d build/classes src/env/ScanEnvironment.java
sleep 2
javac -cp "./libs/jason-3.3.0.jar:./build/classes" -d build/classes Main.java
sleep 2
