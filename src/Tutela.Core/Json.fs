namespace Tutela.Core

open System
open System.Globalization
open System.Text
open System.Text.Json

/// An immutable JSON value. Assessments, policies and catalogs are untrusted
/// input: the gate inspects them as plain data and never as instructions.
/// Object members keep their document order so error ordering is stable.
type JsonValue =
    | JNull
    | JBool of bool
    | JNumber of decimal
    | JString of string
    | JArray of JsonValue list
    | JObject of (string * JsonValue) list

/// Pure JSON helpers. Parsing and serialization use the BCL System.Text.Json
/// reader/writer only; no file, clock or process effects live here.
module Json =
    let rec private ofElement (e: JsonElement) =
        match e.ValueKind with
        | JsonValueKind.Null | JsonValueKind.Undefined -> JNull
        | JsonValueKind.True -> JBool true
        | JsonValueKind.False -> JBool false
        | JsonValueKind.Number ->
            match e.TryGetDecimal() with
            | true, d -> JNumber d
            | _ -> JNumber (decimal (e.GetDouble()))
        | JsonValueKind.String -> JString (e.GetString())
        | JsonValueKind.Array -> e.EnumerateArray() |> Seq.map ofElement |> Seq.toList |> JArray
        | _ -> e.EnumerateObject() |> Seq.map (fun p -> p.Name, ofElement p.Value) |> Seq.toList |> JObject

    /// Parses JSON text. Malformed text is an Error, never an exception.
    let parse (text: string) : Result<JsonValue, string> =
        try
            use doc = JsonDocument.Parse(text)
            Ok (ofElement doc.RootElement)
        with ex -> Error ex.Message

    /// Object member lookup. The last duplicate wins, matching Python dicts.
    let get (key: string) = function
        | JObject members -> members |> List.tryFindBack (fun (k, _) -> k = key) |> Option.map snd
        | _ -> None

    /// Python-style lookup with a default used only when the key is absent.
    let getOr key fallback value = get key value |> Option.defaultValue fallback

    /// Python truthiness: null, false, 0, "", [] and {} are falsy.
    let truthy = function
        | JNull -> false
        | JBool b -> b
        | JNumber n -> n <> 0m
        | JString s -> s <> ""
        | JArray xs -> not xs.IsEmpty
        | JObject ms -> not ms.IsEmpty

    /// `value.get(key)` interpreted with Python truthiness.
    let has key value = get key value |> Option.exists truthy

    /// `x.get(key) is True`.
    let isTrue key value = get key value = Some (JBool true)

    let tryString = function JString s -> Some s | _ -> None
    let stringOf key value = get key value |> Option.bind tryString
    let isObject = function JObject _ -> true | _ -> false

    /// Elements when the value is an array; otherwise empty.
    let items = function JArray xs -> xs | _ -> []

    /// String elements of an array member; other values are ignored.
    let strings key value = get key value |> Option.map items |> Option.defaultValue [] |> List.choose tryString

    /// `value.get(key) or default` for arrays/objects.
    let orEmptyObject key value = match get key value with Some v when truthy v -> v | _ -> JObject []
    let orEmptyArray key value = match get key value with Some v when truthy v -> v | _ -> JArray []

    /// Canonical form for value comparison: object members sorted by key with
    /// the last duplicate winning, so equality matches Python dict equality.
    let rec normalize = function
        | JObject ms -> ms |> List.fold (fun (m: Map<string, JsonValue>) (k, v) -> m.Add(k, normalize v)) Map.empty |> Map.toList |> JObject
        | JArray xs -> JArray (List.map normalize xs)
        | v -> v

    /// Python `==` between two optional values (absent is None).
    let equalOpt (a: JsonValue option) (b: JsonValue option) = Option.map normalize a = Option.map normalize b

    /// Python `str()` rendering, used only where the reference oracle embeds a
    /// raw value in a message (for example `str(None)` is "None").
    let rec pyStr = function
        | JNull -> "None"
        | JBool true -> "True"
        | JBool false -> "False"
        | JNumber n when n = Math.Truncate n -> (Math.Truncate n).ToString("0", CultureInfo.InvariantCulture)
        | JNumber n -> n.ToString(CultureInfo.InvariantCulture)
        | JString s -> s
        | JArray xs -> "[" + (xs |> List.map pyRepr |> String.concat ", ") + "]"
        | JObject ms -> "{" + (ms |> List.map (fun (k, v) -> $"'{k}': {pyRepr v}") |> String.concat ", ") + "}"
    and private pyRepr = function
        | JString s -> $"'{s}'"
        | v -> pyStr v

    let pyStrOpt = function Some v -> pyStr v | None -> "None"

    let private writeValue (writer: Utf8JsonWriter) =
        let rec go value =
            match value with
            | JNull -> writer.WriteNullValue()
            | JBool b -> writer.WriteBooleanValue b
            | JNumber n -> writer.WriteNumberValue n
            | JString s -> writer.WriteStringValue s
            | JArray xs ->
                writer.WriteStartArray()
                xs |> List.iter go
                writer.WriteEndArray()
            | JObject ms ->
                writer.WriteStartObject()
                ms |> List.iter (fun (k, v) -> writer.WritePropertyName k; go v)
                writer.WriteEndObject()
        go

    /// Serializes deterministically (member order preserved, invariant culture).
    let serialize (indented: bool) (value: JsonValue) =
        use stream = new IO.MemoryStream()
        let options = JsonWriterOptions(Indented = indented)
        using (new Utf8JsonWriter(stream, options)) (fun writer -> writeValue writer value; writer.Flush())
        Encoding.UTF8.GetString(stream.ToArray())

    let str (s: string) = JString s
    let strList (xs: string seq) = xs |> Seq.map JString |> Seq.toList |> JArray
    let opt f = function Some x -> f x | None -> JNull
