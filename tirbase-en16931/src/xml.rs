// SPDX-License-Identifier: Apache-2.0

//! Deterministic XML writing and a small XML reader.
//!
//! The writer emits a fixed layout — declaration, two-space indentation, `\n`
//! line endings, attributes in the order given — so serializing the same document
//! twice produces the same bytes.
//!
//! The reader exists for validation: it parses the documents this crate emits back
//! into a tree so structural checks and figure checks run on the serialized text,
//! not on the model that produced it. It accepts namespaces, attributes, UTF-8
//! text, the five predefined entities and numeric character references, and it
//! refuses a document that is not well-formed.

use std::collections::BTreeMap;

/// Declaration every document starts with.
pub const DECLARATION: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>";

/// Escape text content.
pub fn escape_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            _ => output.push(character),
        }
    }
    output
}

/// Escape an attribute value.
pub fn escape_attr(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for character in input.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&apos;"),
            _ => output.push(character),
        }
    }
    output
}

/// A deterministic XML writer.
#[derive(Debug, Default)]
pub struct Writer {
    output: String,
    depth: usize,
}

impl Writer {
    /// A writer with the XML declaration.
    pub fn new() -> Self {
        let mut writer = Self::default();
        writer.output.push_str(DECLARATION);
        writer.output.push('\n');
        writer
    }

    /// Open an element.
    pub fn open(&mut self, name: &str, attributes: &[(&str, &str)]) {
        self.indent();
        self.output.push('<');
        self.output.push_str(name);
        self.attributes(attributes);
        self.output.push_str(">\n");
        self.depth += 1;
    }

    /// Close an element.
    pub fn close(&mut self, name: &str) {
        self.depth = self.depth.saturating_sub(1);
        self.indent();
        self.output.push_str("</");
        self.output.push_str(name);
        self.output.push_str(">\n");
    }

    /// An element with text content.
    pub fn element(&mut self, name: &str, attributes: &[(&str, &str)], text: &str) {
        self.indent();
        self.output.push('<');
        self.output.push_str(name);
        self.attributes(attributes);
        self.output.push('>');
        self.output.push_str(&escape_text(text));
        self.output.push_str("</");
        self.output.push_str(name);
        self.output.push_str(">\n");
    }

    /// An empty element.
    pub fn empty(&mut self, name: &str, attributes: &[(&str, &str)]) {
        self.indent();
        self.output.push('<');
        self.output.push_str(name);
        self.attributes(attributes);
        self.output.push_str("/>\n");
    }

    /// The finished document.
    pub fn finish(self) -> String {
        self.output
    }

    fn indent(&mut self) {
        for _ in 0..self.depth {
            self.output.push_str("  ");
        }
    }

    fn attributes(&mut self, attributes: &[(&str, &str)]) {
        for (name, value) in attributes {
            self.output.push(' ');
            self.output.push_str(name);
            self.output.push_str("=\"");
            self.output.push_str(&escape_attr(value));
            self.output.push('"');
        }
    }
}

/// Why a document could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError {
    /// Byte offset where parsing stopped.
    pub position: usize,
    /// What was wrong.
    pub detail: String,
}

impl std::fmt::Display for XmlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "xml error at byte {}: {}", self.position, self.detail)
    }
}

impl std::error::Error for XmlError {}

/// One parsed element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Qualified name as written (`cbc:ID`).
    pub name: String,
    /// Attributes by name.
    pub attributes: BTreeMap<String, String>,
    /// Concatenated text content.
    pub text: String,
    /// Child elements, in document order.
    pub children: Vec<Node>,
}

impl Node {
    /// The first child with `name`.
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|child| child.name == name)
    }

    /// Every child with `name`.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Node> {
        self.children.iter().filter(move |child| child.name == name)
    }

    /// The trimmed text of the first child with `name`.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|child| child.text.trim())
    }

    /// An attribute value.
    pub fn attribute(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }

    /// This element's trimmed text.
    pub fn text_trimmed(&self) -> &str {
        self.text.trim()
    }

    /// The child names in document order.
    pub fn child_names(&self) -> Vec<&str> {
        self.children
            .iter()
            .map(|child| child.name.as_str())
            .collect()
    }
}

/// Parse a document into its root element.
pub fn parse(input: &str) -> Result<Node, XmlError> {
    let mut parser = Parser { input, position: 0 };
    parser.skip_prolog()?;
    if parser.input[parser.position..].is_empty() {
        return Err(parser.error("the document has no root element"));
    }
    let root = parser.parse_element()?;
    parser.skip_prolog()?;
    if !parser.input[parser.position..].is_empty() {
        return Err(parser.error("trailing content after the root element"));
    }
    Ok(root)
}

struct Parser<'a> {
    input: &'a str,
    position: usize,
}

impl<'a> Parser<'a> {
    fn error(&self, detail: &str) -> XmlError {
        XmlError {
            position: self.position,
            detail: detail.to_string(),
        }
    }

    fn rest(&self) -> &'a str {
        &self.input[self.position..]
    }

    fn skip_whitespace(&mut self) {
        while let Some(character) = self.rest().chars().next() {
            if character.is_whitespace() {
                self.position += character.len_utf8();
            } else {
                break;
            }
        }
    }

    /// Skip whitespace, the declaration and comments.
    fn skip_prolog(&mut self) -> Result<(), XmlError> {
        loop {
            self.skip_whitespace();
            let rest = self.rest();
            if rest.starts_with("<?") {
                let Some(end) = rest.find("?>") else {
                    return Err(self.error("unterminated processing instruction"));
                };
                self.position += end + 2;
            } else if rest.starts_with("<!--") {
                let Some(end) = rest.find("-->") else {
                    return Err(self.error("unterminated comment"));
                };
                self.position += end + 3;
            } else if rest.starts_with("<!") {
                return Err(self.error("a doctype or markup declaration is not accepted"));
            } else {
                return Ok(());
            }
        }
    }

    fn parse_name(&mut self) -> Result<&'a str, XmlError> {
        let rest = self.rest();
        let end = rest
            .find(|character: char| {
                character.is_whitespace() || matches!(character, '>' | '/' | '=' | '<')
            })
            .ok_or_else(|| self.error("unterminated name"))?;
        if end == 0 {
            return Err(self.error("empty name"));
        }
        let name = &rest[..end];
        if !name.chars().all(|character| {
            character.is_alphanumeric() || matches!(character, ':' | '-' | '_' | '.')
        }) {
            return Err(self.error("invalid character in a name"));
        }
        self.position += end;
        Ok(name)
    }

    fn parse_element(&mut self) -> Result<Node, XmlError> {
        if !self.rest().starts_with('<') {
            return Err(self.error("expected an element"));
        }
        self.position += 1;
        let name = self.parse_name()?.to_string();
        let mut attributes = BTreeMap::new();
        loop {
            self.skip_whitespace();
            if self.rest().starts_with("/>") {
                self.position += 2;
                return Ok(Node {
                    name,
                    attributes,
                    text: String::new(),
                    children: Vec::new(),
                });
            }
            if self.rest().starts_with('>') {
                self.position += 1;
                break;
            }
            let attribute = self.parse_name()?.to_string();
            self.skip_whitespace();
            if !self.rest().starts_with('=') {
                return Err(self.error("an attribute needs a value"));
            }
            self.position += 1;
            self.skip_whitespace();
            let quote = self
                .rest()
                .chars()
                .next()
                .filter(|character| matches!(character, '"' | '\''))
                .ok_or_else(|| self.error("an attribute value must be quoted"))?;
            self.position += quote.len_utf8();
            let Some(end) = self.rest().find(quote) else {
                return Err(self.error("unterminated attribute value"));
            };
            let raw = &self.rest()[..end];
            self.position += end + quote.len_utf8();
            if attributes
                .insert(attribute.clone(), decode_entities(raw, self.position)?)
                .is_some()
            {
                return Err(self.error(&format!("duplicate attribute {attribute:?}")));
            }
        }

        let mut text = String::new();
        let mut children = Vec::new();
        loop {
            let rest = self.rest();
            if rest.is_empty() {
                return Err(self.error("unterminated element"));
            }
            if rest.starts_with("</") {
                self.position += 2;
                let closing = self.parse_name()?;
                if closing != name {
                    return Err(self.error(&format!(
                        "closing element {closing:?} does not match {name:?}"
                    )));
                }
                self.skip_whitespace();
                if !self.rest().starts_with('>') {
                    return Err(self.error("malformed closing tag"));
                }
                self.position += 1;
                return Ok(Node {
                    name,
                    attributes,
                    text,
                    children,
                });
            }
            if rest.starts_with("<!--") {
                let Some(end) = rest.find("-->") else {
                    return Err(self.error("unterminated comment"));
                };
                self.position += end + 3;
                continue;
            }
            if rest.starts_with("<![CDATA[") {
                let Some(end) = rest.find("]]>") else {
                    return Err(self.error("unterminated CDATA section"));
                };
                text.push_str(&rest[9..end]);
                self.position += end + 3;
                continue;
            }
            if rest.starts_with("<?") {
                return Err(self.error("a processing instruction is not accepted here"));
            }
            if rest.starts_with('<') {
                children.push(self.parse_element()?);
                continue;
            }
            let end = rest.find('<').unwrap_or(rest.len());
            let raw = &rest[..end];
            text.push_str(&decode_entities(raw, self.position)?);
            self.position += end;
        }
    }
}

fn decode_entities(raw: &str, position: usize) -> Result<String, XmlError> {
    if !raw.contains('&') {
        return Ok(raw.to_string());
    }
    let mut output = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(ampersand) = rest.find('&') {
        output.push_str(&rest[..ampersand]);
        rest = &rest[ampersand..];
        let Some(end) = rest.find(';') else {
            return Err(XmlError {
                position,
                detail: "unterminated entity reference".to_string(),
            });
        };
        let entity = &rest[1..end];
        let decoded = match entity {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code = entity
                    .strip_prefix("#x")
                    .or_else(|| entity.strip_prefix("#X"))
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
                    .or_else(|| {
                        entity
                            .strip_prefix('#')
                            .and_then(|decimal| decimal.parse::<u32>().ok())
                    })
                    .and_then(char::from_u32)
                    .ok_or_else(|| XmlError {
                        position,
                        detail: format!("unknown entity &{entity};"),
                    })?;
                code
            }
        };
        output.push(decoded);
        rest = &rest[end + 1..];
    }
    output.push_str(rest);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_layout_is_fixed_and_escaped() {
        let mut writer = Writer::new();
        writer.open("Invoice", &[("xmlns", "urn:test")]);
        writer.element("cbc:ID", &[], "A&B <1>");
        writer.empty("cbc:Note", &[("lang", "en")]);
        writer.close("Invoice");
        let xml = writer.finish();
        assert_eq!(
            xml,
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Invoice xmlns=\"urn:test\">\n  <cbc:ID>A&amp;B &lt;1&gt;</cbc:ID>\n  <cbc:Note lang=\"en\"/>\n</Invoice>\n"
        );
    }

    #[test]
    fn reader_round_trips_a_written_document() {
        let mut writer = Writer::new();
        writer.open("root", &[]);
        writer.element("a", &[("x", "1 & 2")], "text & more");
        writer.close("root");
        let node = parse(&writer.finish()).expect("parses");
        assert_eq!(node.name, "root");
        assert_eq!(node.child_text("a"), Some("text & more"));
        assert_eq!(
            node.child("a").and_then(|child| child.attribute("x")),
            Some("1 & 2")
        );
    }

    #[test]
    fn malformed_documents_are_refused() {
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("<a>").is_err());
        assert!(parse("text").is_err());
        assert!(parse("<a>&bogus;</a>").is_err());
        assert!(parse("<!DOCTYPE x><a/>").is_err());
        assert!(parse("<a/>trailing").is_err());
        assert!(parse("<a x='1' x='2'/>").is_err());
        assert_eq!(parse("<a x='1'/>").expect("valid").child_names().len(), 0);
    }
}
