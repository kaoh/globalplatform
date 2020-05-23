# Summary

This module contains the Hello World applet.

# Compilation

## Prerequisites

### Java Card 2

Java Card 2.1.2 must be installed and the environment variable `JC212_HOME` must point to this directory.

#### Java 9+ Support 

The compiler of Java 9+ is producing code with an unsupported class format. Due to this a Java 8 SDK must be installed.
In the Maven's `settings.xml` a profile must be created to pint to the SDK:

```xml
    <profiles>
        <profile>
            <id>compiler</id>
            <properties>
                <JAVA_8_HOME>/usr/lib/jvm/java-1.8.0-amazon-corretto</JAVA_8_HOME>
            </properties>
        </profile>
    </profiles>

    <activeProfiles>
        <activeProfile>compiler</activeProfile>
    </activeProfiles>
```

### Java Card 3

Java Card 3 can be used. 

Java Card Development Kit Tools (12_Dec_2019) must be installed and the environment 
variable `JC310_HOME` must point to this directory.

The Maven profile `jc3` must be activated:

Run:

    mvn clean install -P jc3

# Cyberflex Cards

The profile `cflex` must be activated to get a transformed CAP file.

# Compilation

Run:

    mvn clean install
        
In the `target` directory you can find the file `helloworld.cap` to be downloaded to the UICC.
