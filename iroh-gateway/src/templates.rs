pub const dir_list: &str = "
<div>
    <ol>
        {{#each links}}
        <li>
            <a href=\"{{this.path}}\">{{this.name}}</a>
        </li>
        {{/each}}
    </ol>
</div>";

pub const not_found: &str = "
<div>
    <h1>404 Not Found</h1>
    <p>
        The requested resource was not found.
    </p>
</div>
";