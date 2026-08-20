//! Лексический разбор «путеподобных» значений: путей и URL.
//!
//! Существует потому, что `starts_with` по строке — НЕ граница каталога, а
//! правило `path = { prefix = "C:/work/zastava" }` продаётся именно как
//! граница. Строковое сравнение пропускает и `C:/work/zastava/../../Users`,
//! и соседний каталог `C:/work/zastava-private`, чьё имя просто начинается
//! так же. Оба случая воспроизведены на живом гейтвее тремя независимыми
//! ревью M3 — это была дыра в самом гейте, а не в его углу.
//!
//! Разбор ЛЕКСИЧЕСКИЙ: `..` схлопывается по тексту, без обращения к
//! файловой системе (домен не делает IO). Отсюда честное ограничение:
//! символическая ссылка ВНУТРИ разрешённого каталога, ведущая наружу, этой
//! проверкой не ловится. Застава — слой политики, а не песочница.

/// Разобранное путеподобное значение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Корень: `"/"`, `"C:/"`, `"//"` (UNC), `"scheme://authority"` или `""`
    /// для относительного значения.
    pub root: String,
    /// Компоненты после корня, с уже схлопнутыми `.` и `..`.
    pub components: Vec<String>,
}

impl Resolved {
    /// Собирает значение обратно в строку.
    pub fn render(&self) -> String {
        if self.components.is_empty() {
            return self.root.clone();
        }
        let joined = self.components.join("/");
        if self.root.is_empty() || self.root.ends_with('/') {
            format!("{}{joined}", self.root)
        } else {
            // URL-корень хранится без хвостового слеша: `https://host`.
            format!("{}/{joined}", self.root)
        }
    }

    /// Первые `limit` компонентов. Второй элемент — было ли усечение.
    pub fn truncated(&self, limit: usize) -> (Resolved, bool) {
        if self.components.len() <= limit {
            return (self.clone(), false);
        }
        (
            Resolved {
                root: self.root.clone(),
                components: self.components[..limit].to_vec(),
            },
            true,
        )
    }
}

/// Лексически разбирает значение.
///
/// `None` означает «значению нельзя доверять как адресу»: оно выходит за
/// собственный корень (`C:/work/../../Windows`), содержит закодированный
/// обход или задано относительно текущего каталога диска. Всё это осознанно
/// fail-closed — такое значение не совпадёт ни с одним префиксным правилом.
pub fn resolve(raw: &str) -> Option<Resolved> {
    // URL опознаётся ДО замены обратных слешей. Иначе
    // `https://api.example.com\@evil.tld/x` у нас разбирался как хост
    // `api.example.com`, а у Python/Go/Java — как `evil.tld`: гейт разрешал
    // вызов к одному хосту, а downstream шёл к другому (находка верификации
    // M3, классический обход allow-листа хостов).
    if is_url_shaped(raw) {
        // Отказ разбора URL — это отказ ЦЕЛИКОМ, а не повод разобрать его как
        // путь: иначе `https://host\@evil.tld` просто проваливался в путевую
        // ветку, там обратный слеш становился обычным разделителем, и
        // значение снова совпадало с правилом.
        let (root, rest) = url_root(raw)?;
        return finish(root, &rest.replace('\\', "/"));
    }
    let unified = raw.replace('\\', "/");
    let (root, rest) = split_root(&unified)?;
    finish(root, rest)
}

fn finish(root: String, rest: &str) -> Option<Resolved> {
    let mut components: Vec<String> = Vec::new();
    for part in rest.split('/') {
        match part {
            "" | "." => continue,
            ".." => {
                // Выход за корень — не «наверх до бесконечности», а отказ:
                // иначе `C:/work/../../x` тихо стало бы `C:/x`.
                components.pop()?;
            }
            other => {
                // Закодированный обход. Сами мы его не декодируем, но
                // downstream может — и тогда гейт проверил бы один путь, а
                // выполнен был бы другой.
                if contains_encoded_separator(other) {
                    return None;
                }
                components.push(other.to_string());
            }
        }
    }
    Some(Resolved { root, components })
}

fn contains_encoded_separator(part: &str) -> bool {
    let lower = part.to_ascii_lowercase();
    lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c")
}

/// Похоже ли значение на URL: непустая корректная схема перед `://`.
fn is_url_shaped(raw: &str) -> bool {
    match raw.find("://") {
        Some(end) if end > 0 => raw[..end]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.'),
        _ => false,
    }
}

/// Корень URL: `scheme://authority`. `None` — authority не разбирается
/// однозначно, и гадать, чей разбор победит, мы не станем.
fn url_root(raw: &str) -> Option<(String, &str)> {
    let scheme_end = raw.find("://")?;
    let scheme = &raw[..scheme_end];
    let after = &raw[scheme_end + 3..];
    let authority_len = after.find(['/', '?', '#']).unwrap_or(after.len());
    let (authority, rest) = after.split_at(authority_len);
    // Обратный слеш внутри authority — источник расхождения парсеров.
    // Отказываемся целиком, а не гадаем, чей разбор победит.
    if authority.contains('\\') {
        return None;
    }
    Some((format!("{scheme}://{authority}"), rest))
}

/// Отделяет корень от остатка (для не-URL значений).
fn split_root(unified: &str) -> Option<(String, &str)> {
    // UNC: //server/share.
    if let Some(rest) = unified.strip_prefix("//") {
        return Some(("//".to_string(), rest));
    }
    if let Some(rest) = unified.strip_prefix('/') {
        return Some(("/".to_string(), rest));
    }
    // Windows-диск: C: или C:/.
    let bytes = unified.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        let drive = &unified[..2];
        let rest = &unified[2..];
        return match rest.strip_prefix('/') {
            Some(absolute) => Some((format!("{drive}/"), absolute)),
            None if rest.is_empty() => Some((format!("{drive}/"), rest)),
            // `C:work` — путь относительно ТЕКУЩЕГО каталога диска, а он нам
            // неизвестен. Считать его за `C:/work` значит утверждать про
            // место, которого мы не знаем (находка верификации M3).
            None => None,
        };
    }
    Some((String::new(), unified))
}

impl Resolved {
    /// Это URL, а не путь.
    pub fn is_url(&self) -> bool {
        self.root.contains("://")
    }

    /// Windows-пространство имён, где регистр не различается целиком.
    fn is_windows_namespace(&self) -> bool {
        self.root.ends_with(":/") || self.root == "//"
    }

    /// Ключ для сравнения префиксов.
    ///
    /// Регистр складывается ровно там, где его не различает само пространство
    /// имён: на Windows `C:\Work` и `c:/work` — одно место, а на POSIX
    /// `/home/alice/PROJ` — ДРУГОЙ каталог, и складывать регистр там значит
    /// молча расширять правило за пределы написанного (находка верификации
    /// M3). Решение зависит от самого значения, а не от текущей ОС: политика
    /// обязана значить одно и то же на любой машине.
    pub fn compare_key(&self) -> String {
        let case_insensitive_root = self.is_windows_namespace() || self.is_url();
        let root = if case_insensitive_root {
            self.root.to_lowercase()
        } else {
            self.root.clone()
        };
        let fold_components = self.is_windows_namespace();
        let components: Vec<String> = self
            .components
            .iter()
            .map(|c| {
                if fold_components {
                    c.to_lowercase()
                } else {
                    c.clone()
                }
            })
            .collect();
        Resolved { root, components }.render()
    }

    /// Символы, на которых заканчивается компонент этого значения.
    ///
    /// `?` и `#` — граница ТОЛЬКО в URL. Для файловых путей это обычные
    /// символы имени: пока они считались границей везде, каталог
    /// `C:/work/zastava#private` проходил под правилом на `C:/work/zastava`,
    /// а через junction это давало доступ ко всему диску (P1 верификации M3).
    pub fn is_boundary(&self, c: char) -> bool {
        c == '/' || (self.is_url() && (c == '?' || c == '#'))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(raw: &str) -> Option<String> {
        resolve(raw).map(|r| r.render())
    }

    #[test]
    fn dot_dot_is_collapsed_lexically() {
        assert_eq!(
            rendered("C:/work/zastava/../notes.md").unwrap(),
            "C:/work/notes.md"
        );
        assert_eq!(rendered("C:/work/./zastava").unwrap(), "C:/work/zastava");
    }

    #[test]
    fn escaping_the_root_is_refused_not_clamped() {
        // Молчаливое «упереться в корень» превратило бы обход в разрешённый
        // путь; отказ оставляет вызов непокрытым и уводит его в default deny.
        assert!(resolve("C:/work/../../Windows/System32").is_none());
        assert!(resolve("../secret").is_none());
        assert!(resolve("/../etc/shadow").is_none());
    }

    #[test]
    fn windows_backslashes_and_drive_letters_normalize() {
        assert_eq!(
            rendered(r"C:\work\zastava\src").unwrap(),
            "C:/work/zastava/src"
        );
        assert_eq!(rendered("C:").unwrap(), "C:/");
    }

    #[test]
    fn unc_root_survives() {
        // Схлопывание ведущего `//` в `/` увело бы UNC-путь в другой корень.
        assert_eq!(
            rendered(r"\\server\share\dir").unwrap(),
            "//server/share/dir"
        );
    }

    #[test]
    fn url_authority_is_the_root() {
        let r = resolve("https://api.example.com/v1/users?page=2").unwrap();
        assert_eq!(r.root, "https://api.example.com");
        assert_eq!(r.components, vec!["v1", "users?page=2"]);
        assert_eq!(r.render(), "https://api.example.com/v1/users?page=2");
    }

    #[test]
    fn relative_paths_have_no_root() {
        let r = resolve("src/main.rs").unwrap();
        assert_eq!(r.root, "");
        assert_eq!(r.render(), "src/main.rs");
    }

    #[test]
    fn trailing_slash_does_not_change_the_value() {
        assert_eq!(rendered("/home/alice/proj/").unwrap(), "/home/alice/proj");
        assert_eq!(rendered("/home/alice//proj").unwrap(), "/home/alice/proj");
    }

    #[test]
    fn url_with_backslash_in_authority_is_refused() {
        assert!(resolve(r"https://api.example.com\@evil.tld/x").is_none());
        assert!(resolve("https://api.example.com/a\\b").is_some());
    }

    #[test]
    fn drive_relative_paths_are_refused() {
        // `C:work` — относительно текущего каталога диска: место нам неизвестно.
        assert!(resolve("C:work/x").is_none());
        assert!(resolve("C:/work/x").is_some());
    }

    #[test]
    fn percent_encoded_separators_are_refused() {
        assert!(resolve("C:/work/%2e%2e/Windows").is_none());
        assert!(resolve("C:/work/a%2fb").is_none());
    }

    #[test]
    fn case_folding_follows_the_namespace_not_the_host_os() {
        let win = resolve(r"C:\Work\Zastava").unwrap();
        assert_eq!(win.compare_key(), "c:/work/zastava");
        let posix = resolve("/home/Alice/Proj").unwrap();
        assert_eq!(
            posix.compare_key(),
            "/home/Alice/Proj",
            "POSIX различает регистр"
        );
        let url = resolve("https://API.Example.COM/Path").unwrap();
        assert_eq!(
            url.compare_key(),
            "https://api.example.com/Path",
            "хост регистронезависим, путь — нет"
        );
    }

    #[test]
    fn boundaries_depend_on_whether_the_value_is_a_url() {
        assert!(resolve("https://h/x").unwrap().is_boundary('?'));
        assert!(!resolve("C:/work/x").unwrap().is_boundary('?'));
        assert!(!resolve("C:/work/x").unwrap().is_boundary('#'));
        assert!(resolve("C:/work/x").unwrap().is_boundary('/'));
    }

    #[test]
    fn truncation_keeps_the_root() {
        let (short, cut) = resolve(r"C:\path\to\zastava\README.md")
            .unwrap()
            .truncated(3);
        assert!(cut);
        // Буква диска — корень, а не компонент: иначе на Windows три
        // компонента съедались до `C:/Users/<user>`, то есть до всего профиля.
        assert_eq!(short.render(), "C:/Users/alice/Desktop");
    }
}
