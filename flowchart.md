graph LR
    A[Start] --> B(Attempt Imports: AWX/AAP Modules)
    B --> C{Imports Fail?}
    C -- Yes --> D[Print Error, Exit]
    D --> E[End]
    C -- No --> F(Define Functions: list_used_credential_types, decrypt_credentials_by_type, decrypt_all_used_types)
    F --> G(Enter main())
    G --> H[Prompt: List Credential Types? (y/n)]
    H --> I{User Input = 'y'?}
    I -- Yes --> J[list_used_credential_types(), print types]
    J --> K[Prompt: Decrypt Specific ('s'), All ('a'), or Skip?]
    I -- No --> K
    K --> L{User Input = 's'?}
    L -- Yes --> M[Get Used Types, No Types? --> Exit, Present list of types, Prompt Cred Type ID]
    M --> N{Valid ID?}
    N -- Yes --> O[decrypt_credentials_by_type(), all_decrypted = Result]
    N -- No --> P[Print Error, Exit]
    O --> Q[all_decrypted is empty?]
    L -- No --> R{User Input = 'a'?}
    R -- Yes --> S[decrypt_all_used_types(), all_decrypted = Result]
     S --> Q
    R -- No --> T[Print Skipped Decryption]
    T --> Q
    Q -- No --> U[Prompt: Output Choice (1,2,3)]
    Q -- Yes --> E
    U --> V{Invalid Choice?}
    V -- Yes --> W[Print Error, Exit]
    V -- No --> X[Convert Credentials to JSON]
    X --> Y{Choice 1 or 3?}
    Y -- Yes --> Z[Print JSON to Standard Output]
        Z --> AA{Choice 2 or 3?}
    Y -- No --> AA
     AA -- Yes --> AB[Prompt Filename, Write JSON to file, Error or Success Message]
    AA -- No --> E
    AB --> E
