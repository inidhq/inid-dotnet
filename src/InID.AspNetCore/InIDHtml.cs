using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.AspNetCore.Razor.TagHelpers;
using Microsoft.Extensions.DependencyInjection;

namespace InID.AspNetCore;

/// <summary>The browser components (@inid/js) as HTML: works in Razor, minimal APIs or any string template.</summary>
public static class InIDHtml
{
    public const string ScriptUrl = "https://cdn.jsdelivr.net/npm/@inid/js@0.1/dist/inid.global.js";

    /// <summary>The script that defines &lt;inid-sign-in&gt;, &lt;inid-user-button&gt; and the other elements.</summary>
    public static string Script() => $"<script src=\"{ScriptUrl}\" defer></script>";

    /// <summary>
    /// &lt;inid-sign-in&gt;: InID's form inside the page (or a button with redirect: true).
    /// apiPath only when the app moved its routes from /api/inid.
    /// </summary>
    public static string SignIn(string? appName = null, string? returnTo = null, string? entrance = null, string? locale = null, bool redirect = false, string? apiPath = null)
    {
        var html = new StringBuilder("<inid-sign-in");
        void Attr(string name, string? value)
        {
            if (!string.IsNullOrEmpty(value)) html.Append(' ').Append(name).Append("=\"").Append(HtmlEncoder.Default.Encode(value)).Append('"');
        }
        Attr("app-name", appName);
        Attr("return-to", returnTo);
        Attr("entrance", entrance);
        Attr("locale", locale);
        Attr("api-path", apiPath is null or InIDConfig.DefaultApiPath ? null : apiPath);
        if (redirect) html.Append(" redirect");
        return html.Append("></inid-sign-in>").ToString();
    }
}

public static class InIDHtmlHelperExtensions
{
    /// <summary>@Html.InIDScript(): the @inid/js script tag.</summary>
    public static IHtmlContent InIDScript(this IHtmlHelper html) => new HtmlString(InIDHtml.Script());

    /// <summary>@Html.InIDSignIn(appName: "Acme"): the sign-in form (api-path from AddInID's settings).</summary>
    public static IHtmlContent InIDSignIn(this IHtmlHelper html, string? appName = null, string? returnTo = null, string? entrance = null, string? locale = null, bool redirect = false)
    {
        var apiPath = html.ViewContext.HttpContext.RequestServices.GetService<InIDClient>()?.ApiPath;
        return new HtmlString(InIDHtml.SignIn(appName, returnTo, entrance, locale, redirect, apiPath));
    }
}

/// <summary>&lt;inid-script /&gt; in a Razor view becomes the @inid/js script tag (@addTagHelper *, InID.AspNetCore).</summary>
[HtmlTargetElement("inid-script", TagStructure = TagStructure.WithoutEndTag)]
public sealed class InIDScriptTagHelper : TagHelper
{
    public override void Process(TagHelperContext context, TagHelperOutput output)
    {
        output.TagName = "script";
        output.TagMode = TagMode.StartTagAndEndTag;
        output.Attributes.SetAttribute("src", InIDHtml.ScriptUrl);
        output.Attributes.SetAttribute(new TagHelperAttribute("defer", null, HtmlAttributeValueStyle.Minimized));
    }
}
