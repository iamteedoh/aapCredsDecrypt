```mermaid
flowchart TB
    A((Start)) --> B[Open AWX/AAP Environment]
    B --> C[Enter awx-manage shell_plus]
    C --> D[Run the script using exec(open('/path/script.py').read())]
    D --> E{1) List all used Credential Types?}
    E -->|Yes| F[List used Credential Types on screen]
    E -->|No| H[Skip listing]

    F --> G[Show user IDs & Names of used Credential Types]
    G --> H

    H --> I{2) Decrypt credentials<br>(specific/all/skip)?}
    I -->|Specific| J[User selects Credential Type ID]
    I -->|All| K[Decrypt all used Credential Types]
    I -->|Skip| U[No decryption]

    J --> L{Is ID valid?}
    L -->|Yes| M[Decrypt credentials for that type]
    L -->|No| X[Invalid ID. Exit]

    M --> O[Store decrypted results]
    K --> O
    U --> W{3) End Script?\n(No credentials decrypted)}
    W --> X[Exit]

    O --> P{Any credentials were decrypted?}
    P -->|Yes| Q[Choose output:\n1) Screen\n2) File\n3) Both]
    P -->|No| V[No creds to display. End]

    Q --> R[If 1: Print on screen]
    R --> S
    Q --> T[If 2: Prompt filename\n& save as JSON]
    T --> S
    Q --> S[If 3: Do both]
    S --> X[End]
