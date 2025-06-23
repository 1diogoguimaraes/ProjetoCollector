*** Settings ***

Library    SeleniumLibrary
Library    Collections
Library    OperatingSystem
Library    BuiltIn
Library    String

*** Variables ***
${BROWSER}    chrome
${LOCALHOST_URL}    http://localhost:3000
${ITEMS_NUMBER}    10


${ADD_ITEM_TAB}    addItemTab
${ITEMS_TAB}    searchTab

@{WORDS}           Mesa    Relogio    Caneca    Sapato    Carro    Máquina de Escrever    Vaso    Telefone    Rádio
@{DESCRIPTIONS}    Em bom estado com poucas marcas de uso    Funciona bem mas não deve ser constantemente usado. Guardar em local escuro    Serve só para exposição    Artigo delicado, não mexer

@{LINKS}    https://stackoverflow.com/questions    https://www.facebook.com/    https://www.youtube.com/

@{ORIGINS}    Colega    Feira Fundão    Porto    Alemanha    America    Covilhã    Amigo
@{VALUES}           100    300    1200    54    12341    11221
@{BRANDS}    Casio    Rollwatch    Mermeid    Midas    Macro    Bells    Prot    Dask
@{MODELS}    3    45    Mend    Sppa    QWERTY    Gir    Ceer    Lands

@{VISIBILITY}      public    private
${ROOT_DIR}       ${CURDIR}${/}test_files
${DOC_DIR}        ${ROOT_DIR}${/}documents
${PHOTO_DIR}      ${ROOT_DIR}${/}photos

${count_item}    0
*** Test Cases ***

Insert Items BD
    Set Selenium Timeout    20 seconds

    Open website collector

    FOR    ${index}    IN RANGE    ${ITEMS_NUMBER}
        Change Tab    ${ADD_ITEM_TAB}
        Insert Data
        ${count_item}=    Evaluate    ${count_item}+1
        Log To Console    ${count_item}
        Log To Console    ------------------------------
    END

    [Teardown]    Close Browser

Delete Data DB
    Open website collector

    Change Tab    ${ITEMS_TAB}
    Delete Data
    [Teardown]    Close Browser


*** Keywords ***

Open website collector
    Open Browser    ${LOCALHOST_URL}    ${BROWSER}
    Click Element    loginBtn
    Wait Until Element Is Visible    username
    Input Text    username    ze
    Input Password    password    Password.123456
    Click Button    //form/button

Change Tab
    [Arguments]    ${CHANGE_TAB}
    Wait Until Element Is Visible     ${CHANGE_TAB}    
    Click Element     ${CHANGE_TAB}
    
Insert Data
    Wait Until Element Is Visible    name    timeout=120

        # Fill text fields with random words
    ${random_index}=    Evaluate    random.randint(0, len(${WORDS}) - 1)    modules=random
    ${name}=            Get From List    ${WORDS}    ${random_index}
    Input Text          id=name          ${name}

    ${random_index}=    Evaluate    random.randint(0, len(${DESCRIPTIONS}) - 1)    modules=random
    ${description}=     Get From List    ${DESCRIPTIONS}    ${random_index}
    Input Text          id=description   ${description}

    ${random_date}=    Evaluate    (__import__('datetime').date(random.randint(1800, 2024), random.randint(1, 12), random.randint(1, 28))).strftime('%d-%m-%Y')    modules=random
    Input Text         id=acquisition_date    ${random_date}

    ${random_index}=    Evaluate    random.randint(0, len(${VALUES}) - 1)    modules=random
    ${cost}=        Get From List    ${VALUES}    ${random_index}
    Input Text          id=cost     ${cost}

    ${random_index}=    Evaluate    random.randint(0, len(${ORIGINS}) - 1)    modules=random
    ${origin}=        Get From List    ${ORIGINS}    ${random_index}
    Input Text          id=origin     ${origin}


    ${upload_docs}=    Evaluate    random.random() > 0.15    modules=random
    Run Keyword If    ${upload_docs}    Upload Random Documents


    ${random_index}=    Evaluate    random.randint(0, len(${LINKS}) - 1)    modules=random
    ${links}=        Get From List    ${LINKS}    ${random_index}
    Input Text          id=links     ${links}


    ${random_index}=    Evaluate    random.randint(0, len(${BRANDS}) - 1)    modules=random
    ${brand}=        Get From List    ${BRANDS}    ${random_index}
    Input Text          id=brand     ${brand}

    ${random_index}=    Evaluate    random.randint(0, len(${MODELS}) - 1)    modules=random
    ${model}=        Get From List    ${MODELS}    ${random_index}
    Input Text          id=model     ${model}


    ${upload_photos}=    Evaluate    random.random() > 0.15    modules=random
    Run Keyword If    ${upload_photos}    Upload Random Fotos




    ${random_index}=    Evaluate    random.randint(0, len(${VISIBILITY}) - 1)    modules=random
    ${visibility}=      Get From List    ${VISIBILITY}    ${random_index}
    Select From List By Value    id=type    ${visibility}


    Scroll Element Into View    //*[@id="addItemForm"]/button
    Sleep    1
    Click Button    //*[@id="addItemForm"]/button
    Log To Console    '${name}, ${description}, ${random_date}, ${cost}, ${origin}, ${upload_docs},${links}, ${brand}, ${model}, ${upload_photos}, ${visibility}' 
    Sleep    20
    ##Wait Until Element Is Visible   //div[@id="formMessage" and contains(text(), "Item added successfully")]



Delete Data
    Wait Until Element Is Visible    locator=//button[contains(@onclick, 'delete')]
    FOR    ${i}    IN RANGE    100
        ${delete_buttons_vis}=    Run Keyword And Return Status    Wait Until Element Is Visible    //button[contains(@onclick, 'delete')]    10
        IF    ${delete_buttons_vis}
            Click Element    (//button[contains(@onclick, 'delete')])[1]
            Wait Until Element Is Visible    confirmDeleteBtn
            Click Button    Sim, eliminar
            Sleep    0.5
        ELSE
            Exit For Loop
        END
    END

Upload Random Documents
    ${doc_files}=     List Files In Directory    ${DOC_DIR}
    ${num_files}=     Evaluate    random.randint(1, 3)    modules=random
    ${selected_docs}=    Create List

    FOR    ${index}    IN RANGE    ${num_files}
        ${i}=             Evaluate    random.randint(0, len(${doc_files}) - 1)    modules=random
        ${doc_file}=      Get From List    ${doc_files}    ${i}
        ${doc_path}=      Join Path    ${DOC_DIR}    ${doc_file}
        Append To List    ${selected_docs}    ${doc_path}
    END
    ${doc_paths}=    Catenate    SEPARATOR=\n    @{selected_docs}
    Choose File       id=documents    ${doc_paths}

Upload Random Fotos
    ${photo_files}=     List Files In Directory    ${PHOTO_DIR}
    ${num_photos}=      Evaluate    random.randint(1, 3)    modules=random
    ${selected_photos}=    Create List

    FOR    ${index}    IN RANGE    ${num_photos}
        ${i}=             Evaluate    random.randint(0, len(${photo_files}) - 1)    modules=random
        ${photo_file}=    Get From List    ${photo_files}    ${i}
        ${photo_path}=    Join Path    ${PHOTO_DIR}    ${photo_file}
        Append To List    ${selected_photos}    ${photo_path}
    END
    ${photo_paths}=    Catenate    SEPARATOR=\n    @{selected_photos}
    Choose File       id=photos    ${photo_paths}
