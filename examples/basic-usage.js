/**
 * Basic Usage Example for PAK (Password Age Kit)
 * 
 * This example demonstrates how to convert a simple shell script to JavaScript.
 */

import { convertToJavaScript, parseShellScript, validateShellScript } from '@kdbx/pak-lib';

const shellScript = `
#!/bin/bash
# Simple password manager functions

# Variables
PA_DIR="~/.local/share/pa"
PA_LENGTH=50

# Functions
pw_add() {
    echo "Adding password for $1"
    if [ -z "$2" ]; then
        echo "Password cannot be empty"
        return 1
    fi
    echo "$2" | age --encrypt -R recipients -o "$PA_DIR/$1.age"
    echo "Password added successfully"
}

pw_show() {
    if [ ! -f "$PA_DIR/$1.age" ]; then
        echo "Password not found: $1"
        return 1
    fi
    age --decrypt -i identity "$PA_DIR/$1.age"
}

pw_list() {
    find "$PA_DIR" -name "*.age" | sed 's/.*\///;s/\.age$//' | sort
}

pw_delete() {
    if [ ! -f "$PA_DIR/$1.age" ]; then
        echo "Password not found: $1"
        return 1
    fi
    rm "$PA_DIR/$1.age"
    echo "Password deleted: $1"
}

# Main logic
case "$1" in
    add)
        pw_add "$2" "$3"
        ;;
    show)
        pw_show "$2"
        ;;
    list)
        pw_list
        ;;
    delete)
        pw_delete "$2"
        ;;
    *)
        echo "Usage: $0 {add|show|list|delete} [name] [password]"
        exit 1
        ;;
esac
`;

// 1. Validate the shell script
console.log('1. Validating shell script...');
const validation = validateShellScript(shellScript);
console.log('Validation result:', validation);

if (!validation.isValid) {
    console.error('Shell script validation failed:', validation.errors);
    process.exit(1);
}

// 2. Parse the shell script
console.log('\n2. Parsing shell script...');
const ast = parseShellScript(shellScript);
console.log('AST structure:', JSON.stringify(ast, null, 2));

// 3. Convert to JavaScript
console.log('\n3. Converting to JavaScript...');
const conversionResult = convertToJavaScript(shellScript, {
    target: 'node',
    ageIntegration: true,
    modernSyntax: true,
    asyncAwait: true,
    typescript: false,
    errorHandling: 'throw'
});

console.log('Conversion warnings:', conversionResult.warnings);
console.log('Dependencies:', conversionResult.dependencies);

// 4. Display the generated JavaScript
console.log('\n4. Generated JavaScript:');
console.log('='.repeat(50));
console.log(conversionResult.code);
console.log('='.repeat(50));

// 5. Save the converted code to a file
import { writeFileSync } from 'fs';
writeFileSync('converted-password-manager.js', conversionResult.code);
console.log('\nGenerated JavaScript saved to: converted-password-manager.js'); 