```mermaid

flowchart TB
    A((Start)) --> B[Open AWX/AAP Environment]
    B --> C[Enter:<br><code>awx-manage shell_plus</code>]
    C --> D[Run the script with:<br><code>exec(open("/path/script.py").read())</code>]
    D --> E{1) List all used Credential Types?}
    E -->|Yes| F[List used Credential Types on screen]
    E -->|No| H[Skip listing]

    F --> G[Show user the IDs and Names of used Credential Types]
    G --> H

    H --> I{2) Decrypt credentials<br> for specific type,<br> all, or skip?}
    I -->|Specific| J[User selects ID of Credential Type]
    I -->|All| K[Decrypt all used Credential Types]
    I -->|Skip| U[No decryption,<br> jump to end]

    J --> L{Is ID valid?}
    L -->|Yes| M[Decrypt credentials<br> for that type]
    L -->|No| X[Invalid ID<br>script exits]

    M --> O[Store decrypted results in memory]
    K --> O
    U --> W{3) End Script?<br>(No credentials decrypted)}
    W --> X[Script exits]
    O --> P{Any credentials decrypted?}
    P -->|Yes| Q[Choose output method:<br>1) Screen<br>2) File<br>3) Both]
    P -->|No| V[No credentials to display<br>script ends]

    Q --> R{If 1: Print on screen}
    R --> S
    Q --> T{If 2: Prompt filename<br> & save as JSON}
    T --> S
    Q --> S{If 3: Do both<br> (print & save)}
    S --> X[End of Script]


```
