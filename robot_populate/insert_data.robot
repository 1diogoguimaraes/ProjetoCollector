*** Settings ***

Library    SeleniumLibrary
Library    Collections
Library    OperatingSystem
Library    BuiltIn
Library    String

*** Variables ***
${BROWSER}    chrome
${LOCALHOST_URL}    http://localhost:3000
${NEW_TAB}    addItemTab

@{WORDS}           Alpha    Bravo    Charlie    Delta    Echo
@{VALUES}           100    300    1200    54    12341    11221
@{VISIBILITY}      public    private
${ROOT_DIR}       ${CURDIR}${/}test_files
${DOC_DIR}        ${ROOT_DIR}${/}documents
${PHOTO_DIR}      ${ROOT_DIR}${/}photos
*** Test Cases ***

Insert Items BD
    Open website collector
    Change Tab    ${NEW_TAB}
    Insert Data
    [Teardown]    Close Browser

*** Keywords ***

Open website collector
    Open Browser    ${LOCALHOST_URL}    ${BROWSER}
    Click Element    loginBtn
    Wait Until Element Is Visible    username
    Input Text    username    ze
    Input Password    password    123
    Click Button    Login

Change Tab
    [Arguments]    ${CHANGE_TAB}
    Wait Until Element Is Visible     ${CHANGE_TAB}    
    Click Element     ${CHANGE_TAB}
    Wait Until Element Is Visible    name

Insert Data
        # Fill text fields with random words
    ${random_index}=    Evaluate    random.randint(0, len(${WORDS}) - 1)    modules=random
    ${name}=            Get From List    ${WORDS}    ${random_index}
    Input Text          id=name          ${name}

    ${random_index}=    Evaluate    random.randint(0, len(${WORDS}) - 1)    modules=random
    ${description}=     Get From List    ${WORDS}    ${random_index}
    Input Text          id=description   ${description}

    ${random_date}=    Evaluate    (__import__('datetime').date(random.randint(1900, 2024), random.randint(1, 12), random.randint(1, 28))).strftime('%d-%m-%Y')    modules=random
    Input Text         id=acquisition_date    ${random_date}
    Log To Console    ${random_date}
    ${random_index}=    Evaluate    random.randint(0, len(${VALUES}) - 1)    modules=random
    ${cost}=        Get From List    ${VALUES}    ${random_index}
    Input Text          id=cost     ${cost}

    ${random_index}=    Evaluate    random.randint(0, len(${WORDS}) - 1)    modules=random
    ${origin}=        Get From List    ${WORDS}    ${random_index}
    Input Text          id=origin     ${origin}


    ${doc_files}=     List Files In Directory    ${DOC_DIR}
    ${i}=             Evaluate    random.randint(0, len(${doc_files}) - 1)    modules=random
    ${doc_file}=      Get From List    ${doc_files}    ${i}
    ${doc_path}=      Join Path    ${DOC_DIR}    ${doc_file}
    Choose File       id=documents    ${doc_path}


    ${random_index}=    Evaluate    random.randint(0, len(${WORDS}) - 1)    modules=random
    ${brand}=        Get From List    ${WORDS}    ${random_index}
    Input Text          id=brand     ${brand}

    ${random_index}=    Evaluate    random.randint(0, len(${WORDS}) - 1)    modules=random
    ${model}=        Get From List    ${WORDS}    ${random_index}
    Input Text          id=model     ${model}


    ${photo_files}=   List Files In Directory    ${PHOTO_DIR}
    ${i}=             Evaluate    random.randint(0, len(${photo_files}) - 1)    modules=random
    ${photo_file}=    Get From List    ${photo_files}    ${i}
    ${photo_path}=    Join Path    ${PHOTO_DIR}    ${photo_file}
    Choose File       id=photos       ${photo_path}


    ${random_index}=    Evaluate    random.randint(0, len(${VISIBILITY}) - 1)    modules=random
    ${visibility}=      Get From List    ${VISIBILITY}    ${random_index}
    Select From List By Value    id=type    ${visibility}


    Sleep    10
    Click Button    Add Item
    Sleep    10

