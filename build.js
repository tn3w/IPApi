import { readFile, writeFile, mkdir } from 'fs/promises';
import { join, basename } from 'path';
import { minify as minifyHtml } from 'html-minifier-terser';
import { minify as minifyJs } from 'terser';
import { minify as minifyCss } from 'csso';
import { glob } from 'glob';
import { createHash } from 'crypto';
import { get as httpsGet } from 'https';
import { get as httpGet } from 'http';

const htmlMinifyOptions = {
    collapseWhitespace: true,
    removeComments: true,
    minifyCSS: true,
    minifyJS: true,
    removeAttributeQuotes: true,
    removeRedundantAttributes: true,
    removeScriptTypeAttributes: true,
    removeStyleLinkTypeAttributes: true,
    useShortDoctype: true,
};

const jsMinifyOptions = {
    compress: {
        passes: 2,
        inline: 3,
        unsafe: true,
        unsafe_comps: true,
        unsafe_math: true,
        unsafe_proto: true,
        unsafe_regexp: true,
        unsafe_undefined: true,
    },
    mangle: true,
    format: { comments: false },
};

async function generateSri(content) {
    const hash = createHash('sha512').update(content).digest('base64');
    return `sha512-${hash}`;
}

async function fetchUrl(url) {
    return new Promise((resolve, reject) => {
        const get = url.startsWith('https://') ? httpsGet : httpGet;
        get(url, (res) => {
            if (res.statusCode !== 200) {
                reject(new Error(`Failed to fetch ${url}: ${res.statusCode}`));
                return;
            }
            let data = '';
            res.on('data', (chunk) => (data += chunk));
            res.on('end', () => resolve(data));
        }).on('error', reject);
    });
}

async function readAndMinifyCss(paths) {
    const contents = await Promise.all(paths.map((path) => readFile(path, 'utf8')));
    const combined = contents.join('\n');
    return minifyCss(combined).css;
}

async function readAndMinifyJs(paths) {
    const contents = await Promise.all(paths.map((path) => readFile(path, 'utf8')));
    const combined = contents.join(';\n');
    const cleaned = cleanMultilineStrings(combined);
    const result = await minifyJs(cleaned, jsMinifyOptions);
    return result.code;
}

function cleanMultilineStrings(code) {
    return code.replace(/(['"`])(\s*\n[\s\S]*?)\1/g, (_, quote, content) => {
        const cleaned = content
            .split('\n')
            .map((line) => line.trim())
            .filter((line) => line.length > 0)
            .join(' ');
        return `${quote}${cleaned}${quote}`;
    });
}

function extractPaths(html, tag, attr) {
    const regex = new RegExp(`<${tag}[^>]*${attr}=["']([^"']+)["'][^>]*>`, 'gi');
    const paths = [];
    let match;

    while ((match = regex.exec(html)) !== null) {
        paths.push(match[1]);
    }

    return paths;
}

function extractInlineStyles(html) {
    const styleRegex = /<style[^>]*>([\s\S]*?)<\/style>/gi;
    const styles = [];
    let match;

    while ((match = styleRegex.exec(html)) !== null) {
        styles.push(match[1]);
    }

    return styles;
}

function extractInlineScripts(html) {
    const scriptRegex = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
    const scripts = [];
    let match;

    while ((match = scriptRegex.exec(html)) !== null) {
        scripts.push(match[1]);
    }

    return scripts;
}

async function processTemplate(templatePath) {
    const html = await readFile(templatePath, 'utf8');
    const templateName = basename(templatePath);

    const allCssLinks = extractPaths(html, 'link', 'href').filter((path) => path.endsWith('.css'));
    const allJsLinks = extractPaths(html, 'script', 'src').filter((path) => path.endsWith('.js'));
    const localCssLinks = allCssLinks.filter(
        (path) => !path.startsWith('http://') && !path.startsWith('https://')
    );
    const localJsLinks = allJsLinks.filter(
        (path) => !path.startsWith('http://') && !path.startsWith('https://')
    );
    const remoteCssLinks = allCssLinks.filter(
        (path) => path.startsWith('http://') || path.startsWith('https://')
    );
    const remoteJsLinks = allJsLinks.filter(
        (path) => path.startsWith('http://') || path.startsWith('https://')
    );
    const inlineStyles = extractInlineStyles(html);
    const inlineScripts = extractInlineScripts(html);

    let processedHtml = html;
    let cssReplaced = false;
    let jsReplaced = false;

    if (localCssLinks.length > 0) {
        const cssPaths = localCssLinks.map((link) => link.replace(/^\//, ''));
        const minifiedCss = await readAndMinifyCss(cssPaths);
        const cssSri = await generateSri(minifiedCss);

        const localCssPattern = localCssLinks
            .map((link) => link.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
            .join('|');
        const cssRegex = new RegExp(`<link[^>]*href=["'](${localCssPattern})["'][^>]*>`, 'gi');
        const replacement = `<style integrity="${cssSri}">${minifiedCss}</style>`;

        processedHtml = processedHtml.replace(cssRegex, () => {
            if (cssReplaced) return '';
            cssReplaced = true;
            return replacement;
        });
    }

    if (localJsLinks.length > 0) {
        const jsPaths = localJsLinks.map((link) => link.replace(/^\//, ''));
        const minifiedJs = await readAndMinifyJs(jsPaths);
        const jsSri = await generateSri(minifiedJs);

        const localJsPattern = localJsLinks
            .map((link) => link.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
            .join('|');
        const jsRegex = new RegExp(
            `<script[^>]*src=["'](${localJsPattern})["'][^>]*><\\/script>`,
            'gi'
        );
        const replacement = `<script integrity="${jsSri}">${minifiedJs}</script>`;

        processedHtml = processedHtml.replace(jsRegex, () => {
            if (jsReplaced) return '';
            jsReplaced = true;
            return replacement;
        });
    }

    for (const url of remoteCssLinks) {
        const content = await fetchUrl(url);
        const sri = await generateSri(content);
        const escapedUrl = url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`<link([^>]*href=["']${escapedUrl}["'][^>]*?)(/?)>`, 'gi');
        processedHtml = processedHtml.replace(
            regex,
            `<link$1 integrity="${sri}" crossorigin="anonymous"$2>`
        );
    }

    for (const url of remoteJsLinks) {
        const content = await fetchUrl(url);
        const sri = await generateSri(content);
        const escapedUrl = url.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const regex = new RegExp(`<script([^>]*src=["']${escapedUrl}["'][^>]*?)>`, 'gi');
        processedHtml = processedHtml.replace(
            regex,
            `<script$1 integrity="${sri}" crossorigin="anonymous">`
        );
    }

    if (inlineStyles.length > 0) {
        const minifiedCss = minifyCss(inlineStyles.join('\n')).css;
        const cssSri = await generateSri(minifiedCss);

        let styleReplaced = false;
        processedHtml = processedHtml.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, () => {
            if (styleReplaced) return '';
            styleReplaced = true;
            return `<style integrity="${cssSri}">${minifiedCss}</style>`;
        });
    }

    if (inlineScripts.length > 0) {
        const cleanedScripts = inlineScripts.map(cleanMultilineStrings);
        const minifiedJs = (await minifyJs(cleanedScripts.join(';\n'), jsMinifyOptions)).code;
        const jsSri = await generateSri(minifiedJs);

        let scriptReplaced = false;
        processedHtml = processedHtml.replace(
            /<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/gi,
            () => {
                if (scriptReplaced) return '';
                scriptReplaced = true;
                return `<script integrity="${jsSri}">${minifiedJs}</script>`;
            }
        );
    }

    const minifiedHtml = await minifyHtml(processedHtml, htmlMinifyOptions);
    await writeFile(join('build', templateName), minifiedHtml);
}

async function build() {
    await mkdir('build', { recursive: true });

    const templates = await glob('templates/**/*.html');

    await Promise.all(templates.map(processTemplate));

    console.log(`Built ${templates.length} template(s)`);
}

build().catch(console.error);
