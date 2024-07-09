#[derive(Debug, Clone)]
pub enum PATTERN {
    McAdd(AddType),
    McChange(ChangeType),
    IfPreAdd,
    IfPostAdd,
    IfCondChange,
    RangeChecker(CheckType),
    MatchChange,
    IndexMutate,
    UnsafeAdd,
    MatchAdd(MatchType),
}

#[derive(Debug, Clone)]
pub enum ChangeType {
    // add -> saturating_add
    ToSaturating,
    // add -> check_add
    ToCheck,
    // add -> wrapping_add
    ToWrapping,
    // map -> filter_map
    ToFilterMap,
    // except -> unwrap
    ToUnwrap,
    // except -> unwrap_or_else
    ToUnwrapOrElse,
    // except -> unwrap_or_fault
    ToUnwrapOrFault,
    // copy_from_slice -> extend_from_slice
    ToExtendFromSlice,
}

#[derive(Debug, Clone)]
pub enum AddType {
    // add as_bytes
    AddAsBytes,
    // add max()
    AddMax,
}

#[derive(Debug, Clone)]
pub enum CheckType {
    // Wrap with a if check
    Wrap,
    // Add a if check before the operation
    PreAdd,
}

#[derive(Debug, Clone)]
pub enum MatchType {
    // return None
    ReturnNone,
    // return Ok(())
    ReturnOk,
    // return Err(())
    ReturnErr,
    // return default
    ReturnDefault,
}

impl std::fmt::Display for PATTERN {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PATTERN::McAdd(add_type) => write!(f, "McAdd({})", add_type),
            PATTERN::McChange(change_type) => write!(f, "McChange({})", change_type),
            PATTERN::IfPreAdd => write!(f, "IfPreAdd"),
            PATTERN::IfPostAdd => write!(f, "IfPostAdd"),
            PATTERN::IfCondChange => write!(f, "IfCondChange"),
            PATTERN::RangeChecker(check_type) => write!(f, "RangeChecker({})", check_type),
            PATTERN::MatchChange => write!(f, "MatchChange"),
            PATTERN::IndexMutate => write!(f, "IndexMutate"),
            PATTERN::UnsafeAdd => write!(f, "UnsafeAdd"),
            PATTERN::MatchAdd(match_type) => write!(f, "MatchAdd({})", match_type),
        }
    }
}

impl std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChangeType::ToSaturating => write!(f, "ToSaturating"),
            ChangeType::ToCheck => write!(f, "ToCheck"),
            ChangeType::ToWrapping => write!(f, "ToWrapping"),
            ChangeType::ToFilterMap => write!(f, "ToFilterMap"),
            ChangeType::ToUnwrap => write!(f, "ToUnwrap"),
            ChangeType::ToUnwrapOrElse => write!(f, "ToUnwrapOrElse"),
            ChangeType::ToUnwrapOrFault => write!(f, "ToUnwrapOrFault"),
            ChangeType::ToExtendFromSlice => write!(f, "ToExtendFromSlice"),
        }
    }
}

impl std::fmt::Display for AddType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddType::AddAsBytes => write!(f, "AddAsBytes"),
            AddType::AddMax => write!(f, "AddMax"),
        }
    }
}

impl std::fmt::Display for CheckType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckType::Wrap => write!(f, "Wrap"),
            CheckType::PreAdd => write!(f, "PreAdd"),
        }
    }
}

impl std::fmt::Display for MatchType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchType::ReturnNone => write!(f, "ReturnNone"),
            MatchType::ReturnOk => write!(f, "ReturnOk"),
            MatchType::ReturnErr => write!(f, "ReturnErr"),
            MatchType::ReturnDefault => write!(f, "ReturnDefault"),
        }
    }
}

impl PATTERN {
    pub fn description(&self) -> String {
        match self {
            PATTERN::McAdd(add_type) => format!(
                "Modifies code to include missing methods or traits, such as adding a method for byte conversion or implementing max() function for comparisons, which can prevent panics related to incorrect type usage or arithmetic overflows, such as {}",
                add_type.description()
            ),
            PATTERN::McChange(change_type) => format!(
                "Changes existing method calls to safer or more suitable versions, addressing issues like arithmetic overflow, improper mapping, or unsafe unwrapping, which can lead to panics, such as {}",
                change_type.description()
            ),
            PATTERN::IfPreAdd => "Adds precondition checks before executing if statements to ensure that conditions like bounds(like begin <= end) or state prerequisites are met, preventing panics caused by violating these conditions.".to_string(),
            PATTERN::IfPostAdd => "Inserts checks after if statements to validate outcomes, ensuring that operations such as indexing or arithmetic calculations have not led to unsafe states or potential panics.".to_string(),
            PATTERN::IfCondChange => "Adjusts conditions within if statements to better handle edge cases or boundary conditions, thus preventing panics due to unexpected values or states.".to_string(),
            PATTERN::RangeChecker(check_type) => format!(
                "Implements range checking for array or vector indices and arithmetic bounds before their usage, preventing panics caused by out-of-bounds errors or arithmetic overflows, such as {}",
                check_type.description()
            ),
            PATTERN::MatchChange => "Enhances pattern matching logic to cover all possible cases comprehensively, including handling of None/Some for Options and Ok/Err for Results, to avoid panics due to unmatched patterns or unexpected values.".to_string(),
            PATTERN::IndexMutate => "Safely mutates indices and employs safer access methods, like get() for arrays, to mitigate panics from out-of-bounds access or boundary conditions errors.".to_string(),
            PATTERN::UnsafeAdd => "Introduces or revises unsafe code blocks with meticulous checks for conditions such as bounds, null pointers, or valid state assumptions, minimizing the risk of panics due to undefined behavior or illegal memory access.".to_string(),
            PATTERN::MatchAdd(match_type) => format!(
                "Adds or revises match arms to handle all possible return types, including None, Ok, Err, or default values, to prevent panics due to unmatched patterns or unexpected return values, such as {}",
                match_type.description()
            ),
        }
    }
}


impl ChangeType {
    pub fn description(&self) -> String {
        match self {
            ChangeType::ToSaturating => "Replaces basic arithmetic operations (add, subtract) with saturating variants (saturating_add, saturating_sub) to handle overflow by saturating at the numeric bounds instead of panicking.".to_string(),
            ChangeType::ToCheck => "Employs checked arithmetic operations (check_add, check_sub) to explicitly handle potential overflow scenarios with Option types, allowing for safe handling of None cases without panicking.".to_string(),
            ChangeType::ToWrapping => "Utilizes wrapping arithmetic operations (wrapping_add, wrapping_sub) that wrap around on overflow, providing a defined behavior for overflow conditions without causing panics.".to_string(),
            ChangeType::ToFilterMap => "Transforms a map operation into filter_map to explicitly handle Option types (None and Some cases), preventing panics by filtering out None values before applying the map function.".to_string(),
            ChangeType::ToUnwrap => "Changes from direct unwrapping (unwrap, expect) to more cautious approaches for handling Options and Results, preventing panics by avoiding unwrapping None or Err values without prior checks.".to_string(),
            ChangeType::ToUnwrapOrElse => "Adopts unwrap_or_else for Options and Results, providing a fallback function to handle None or Err cases lazily, thus avoiding panics by ensuring a default value or action is available.".to_string(),
            ChangeType::ToUnwrapOrFault => "Similar to unwrap_or_else, but focuses on error handling strategies for failure scenarios with Options and Results, aiming to prevent panics by defining explicit error handling paths.".to_string(),
            ChangeType::ToExtendFromSlice => "Prefers extend_from_slice over copy_from_slice for Vec operations, implicitly handling bounds and capacity checks, preventing panics due to exceeding vector bounds.".to_string(),
        }
    }
}


impl AddType {
    pub fn description(&self) -> String {
        match self {
            AddType::AddAsBytes => "Adds as_bytes method to types for converting data to byte slices safely, avoiding potential panics from incorrect manual byte conversions or handling.".to_string(),
            AddType::AddMax => "Incorporates max() function in arithmetic operations, comparisons, or boundary checks to prevent overflows, underflows, or boundary-related panics by ensuring values stay within safe limits.".to_string(),
        }
    }
}

impl CheckType {
    pub fn description(&self) -> String {
        match self {
            CheckType::Wrap => "Wraps the operation with a conditional check to ensure that the operation is only executed when the condition is met, preventing panics due to invalid states or unexpected values.".to_string(),
            CheckType::PreAdd => "Adds a precondition check before the operation to ensure that the condition is met, preventing panics due to invalid states or unexpected values.".to_string(),
        }
    }
}

impl MatchType {
    pub fn description(&self) -> String {
        match self {
            MatchType::ReturnNone => "Returns None for Option types to handle cases where no value is present, preventing panics due to unwrapping None values.".to_string(),
            MatchType::ReturnOk => "Returns Ok(()) for Result types to handle successful operations, preventing panics due to unwrapping Err values.".to_string(),
            MatchType::ReturnErr => "Returns Err(()) for Result types to handle error scenarios, preventing panics due to unwrapping Ok values.".to_string(),
            MatchType::ReturnDefault => "Returns a default value or action for unmatched patterns or unexpected return values, preventing panics due to unexpected states or values.".to_string(),
        }
    }
}