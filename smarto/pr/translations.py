"""
Translations for the Ethereum Security Toolkit
"""

# English to Russian translation dictionary
TRANSLATIONS = {
    'en': {
        # Main UI elements
        'app_title': 'Ethereum Security Toolkit',
        'app_subtitle': 'Analyze Ethereum smart contracts for security vulnerabilities and properties',
        'contract_address': 'Contract Address',
        'network': 'Network',
        'analyze_contract': 'Analyze Contract',
        'analyzing': 'Analyzing...',
        'select_popular': 'Or Select a Popular Contract',
        'select_contract': '-- Select a contract --',
        'progress': 'Progress',
        'language': 'Language',
        
        # Analysis types
        'analysis_type': 'Analysis Type',
        'full_analysis': 'Full Analysis',
        'reentrancy_check': 'Reentrancy Vulnerability Check',
        'bytecode_analysis': 'Bytecode Analysis',
        'contract_relationships': 'Contract Relationships',
        
        # Analysis options
        'analysis_options': 'Analysis Options',
        'skip_reentrancy': 'Skip Reentrancy Vulnerability Check',
        'skip_reentrancy_desc': 'The reentrancy check can be resource-intensive for complex contracts.',
        
        # Analysis results
        'analysis_details': 'Analysis Details',
        'contract_info': 'Contract Information',
        'function_signatures': 'Function Signatures',
        'security_warnings': 'Security Warnings',
        'contract_type': 'Contract Type',
        'token': 'Token',
        'standard_contract': 'Standard Contract',
        'balance': 'Balance',
        'is_proxy': 'Is Proxy',
        'token_info': 'Token Information',
        'name': 'Name',
        'symbol': 'Symbol',
        'decimals': 'Decimals',
        'total_supply': 'Total Supply',
        
        # Security warnings
        'security_warning_title': 'The following potentially dangerous operations were detected in the contract bytecode:',
        'security_warning_note': 'Note: The presence of these operations doesn\'t necessarily mean the contract is vulnerable. A manual code review is recommended to verify the security implications.',
        'delegatecall_warning': 'Use delegatecall only with trusted contracts. Validate the contract being called and ensure it cannot modify critical storage variables.',
        'selfdestruct_warning': 'selfdestruct can be used to remove a contract from the blockchain and send its remaining balance to a specified address. If a contract has a selfdestruct function that can be called by anyone, it can be exploited to drain funds.',
        'tx_origin_warning': 'Using tx.origin for authentication can be exploited if a user unknowingly interacts with a malicious contract that calls the vulnerable contract.',
        
        # Reentrancy
        'reentrancy_title': 'Reentrancy Vulnerability Check',
        'found_issues': 'Found {} potential reentrancy issues:',
        'no_vulnerabilities': 'No obvious reentrancy vulnerabilities detected.',
        
        # Bytecode analysis
        'bytecode_title': 'Bytecode Analysis',
        'disassembled_instr': 'Disassembled Instructions (first 100)',
        'no_bytecode': 'No bytecode analysis available.',
        
        # Contract relationships
        'relationships_title': 'Contract Relationships',
        'child_indicators': 'Found child contract creation operations:',
        'no_child_indicators': 'No direct child contract creation operations detected.',
        'proxy_indicators': 'Proxy contract indicators detected:',
        'proxy_signatures': 'Function signatures indicating proxy:',
        'minimal_proxy': 'EIP-1167 minimal proxy pattern detected.',
        'parent_candidates': 'Potential parent/implementation contracts:',
        'implementation_addresses': 'Potential Implementation Addresses Found in Bytecode',
        'no_relationships': 'No relationship analysis available.',
        
        # Raw data
        'raw_data': 'Raw Analysis Data',
        
        # Errors and warnings
        'toolkit_unavailable': 'Toolkit modules not detected!',
        'toolkit_files_needed': 'Please make sure you\'ve copied these files to the toolkit directory:',
        'toolkit_limited': 'Until these files are available, the analysis functionality will be limited.',
        'analysis_disabled': 'Analysis is disabled until toolkit modules are available.',
        'enter_address': 'Please enter a contract address',
        'skip_reentrancy_error': 'Cannot skip reentrancy check when the analysis type is reentrancy',
        'no_bytecode_found': 'No bytecode found for this address.',
        'modules_missing': 'Required modules are missing. Please make sure info-getter.py and bytecode.py exist in the toolkit directory.'
    },
    'ru': {
        # Main UI elements
        'app_title': 'Инструментарий безопасности Ethereum',
        'app_subtitle': 'Анализ смарт-контрактов Ethereum на наличие уязвимостей и свойств безопасности',
        'contract_address': 'Адрес контракта',
        'network': 'Сеть',
        'analyze_contract': 'Анализировать контракт',
        'analyzing': 'Анализирую...',
        'select_popular': 'Или выберите популярный контракт',
        'select_contract': '-- Выберите контракт --',
        'progress': 'Прогресс',
        'language': 'Язык',
        
        # Analysis types
        'analysis_type': 'Тип анализа',
        'full_analysis': 'Полный анализ',
        'reentrancy_check': 'Проверка на уязвимость повторного входа',
        'bytecode_analysis': 'Анализ байткода',
        'contract_relationships': 'Связи контракта',
        
        # Analysis options
        'analysis_options': 'Параметры анализа',
        'skip_reentrancy': 'Пропустить проверку на уязвимость повторного входа',
        'skip_reentrancy_desc': 'Проверка на повторный вход может быть ресурсоемкой для сложных контрактов.',
        
        # Analysis results
        'analysis_details': 'Детали анализа',
        'contract_info': 'Информация о контракте',
        'function_signatures': 'Сигнатуры функций',
        'security_warnings': 'Предупреждения безопасности',
        'contract_type': 'Тип контракта',
        'token': 'Токен',
        'standard_contract': 'Стандартный контракт',
        'balance': 'Баланс',
        'is_proxy': 'Является прокси',
        'token_info': 'Информация о токене',
        'name': 'Название',
        'symbol': 'Символ',
        'decimals': 'Десятичные',
        'total_supply': 'Общее предложение',
        
        # Security warnings
        'security_warning_title': 'В байткоде контракта обнаружены следующие потенциально опасные операции:',
        'security_warning_note': 'Примечание: Наличие этих операций не обязательно означает, что контракт уязвим. Рекомендуется ручной обзор кода для проверки последствий для безопасности.',
        'delegatecall_warning': 'Используйте delegatecall только с доверенными контрактами. Проверяйте вызываемый контракт и убедитесь, что он не может изменить критически важные переменные хранилища.',
        'selfdestruct_warning': 'selfdestruct может использоваться для удаления контракта из блокчейна и отправки его оставшегося баланса на указанный адрес. Если функция selfdestruct в контракте может быть вызвана кем угодно, это может использоваться для вывода средств.',
        'tx_origin_warning': 'Использование tx.origin для аутентификации может быть уязвимо, если пользователь, не подозревая об этом, взаимодействует с вредоносным контрактом, который вызывает уязвимый контракт.',
        
        # Reentrancy
        'reentrancy_title': 'Проверка на уязвимость повторного входа',
        'found_issues': 'Найдено {} потенциальных проблем повторного входа:',
        'no_vulnerabilities': 'Очевидных уязвимостей повторного входа не обнаружено.',
        
        # Bytecode analysis
        'bytecode_title': 'Анализ байткода',
        'disassembled_instr': 'Дизассемблированные инструкции (первые 100)',
        'no_bytecode': 'Анализ байткода недоступен.',
        
        # Contract relationships
        'relationships_title': 'Связи контракта',
        'child_indicators': 'Найдены операции создания дочерних контрактов:',
        'no_child_indicators': 'Операции прямого создания дочерних контрактов не обнаружены.',
        'proxy_indicators': 'Обнаружены индикаторы прокси-контракта:',
        'proxy_signatures': 'Сигнатуры функций, указывающие на прокси:',
        'minimal_proxy': 'Обнаружен шаблон минимального прокси EIP-1167.',
        'parent_candidates': 'Потенциальные родительские/реализующие контракты:',
        'implementation_addresses': 'Потенциальные адреса реализации, найденные в байткоде',
        'no_relationships': 'Анализ связей недоступен.',
        
        # Raw data
        'raw_data': 'Необработанные данные анализа',
        
        # Errors and warnings
        'toolkit_unavailable': 'Модули инструментария не обнаружены!',
        'toolkit_files_needed': 'Убедитесь, что вы скопировали следующие файлы в каталог toolkit:',
        'toolkit_limited': 'Пока эти файлы недоступны, функциональность анализа будет ограничена.',
        'analysis_disabled': 'Анализ отключен до тех пор, пока модули инструментария не будут доступны.',
        'enter_address': 'Пожалуйста, введите адрес контракта',
        'skip_reentrancy_error': 'Невозможно пропустить проверку повторного входа, когда тип анализа - проверка повторного входа',
        'no_bytecode_found': 'Байткод не найден для этого адреса.',
        'modules_missing': 'Отсутствуют необходимые модули. Убедитесь, что info-getter.py и bytecode.py существуют в каталоге toolkit.'
    }
}

def get_text(key, lang='en'):
    """Get translated text for the given key and language."""
    if lang not in TRANSLATIONS:
        lang = 'en'
    
    return TRANSLATIONS[lang].get(key, TRANSLATIONS['en'].get(key, key)) 