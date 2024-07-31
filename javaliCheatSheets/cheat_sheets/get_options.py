import six
import string
from pwnlib import term

def get_options(prompt, opts, default = None):
    r"""Presents the user with a prompt (typically in the
    form of a question) and a number of options.

    Arguments:
      prompt (str): The prompt to show
      opts (list): The options to show to the user
      default: The default option to choose

    Returns:
      The users choice in the form of an integer.

    Examples:

    .. doctest::
       :skipif: branch_dev

        >>> options("Select a color", ("red", "green", "blue"), "green")
        Traceback (most recent call last):
        ...
        ValueError: get_options(): default must be a number or None

    Tests:

    .. doctest::
       :skipif: branch_dev

        >>> p = testpwnproc("print(options('select a color', ('red', 'green', 'blue')))")
        >>> p.sendline(b"\33[C\33[A\33[A\33[B\33[1;5A\33[1;5B 0310")
        >>> _ = p.recvall()
        >>> saved_stdin = sys.stdin
        >>> try:
        ...     sys.stdin = io.TextIOWrapper(io.BytesIO(b"\n4\n\n3\n"))
        ...     with context.local(log_level="INFO"):
        ...         options("select a color A", ("red", "green", "blue"), 0)
        ...         options("select a color B", ("red", "green", "blue"))
        ... finally:
        ...     sys.stdin = saved_stdin
         [?] select a color A
               1) red
               2) green
               3) blue
             Choice [1] 0
         [?] select a color B
               1) red
               2) green
               3) blue
             Choice  [?] select a color B
               1) red
               2) green
               3) blue
             Choice  [?] select a color B
               1) red
               2) green
               3) blue
             Choice 2
    """

    if default is not None and not isinstance(default, six.integer_types):
        raise ValueError('options(): default must be a number or None')

    if term.term_mode:
        numfmt = '%' + str(len(str(len(opts)))) + 'd) '
        print(' [?] ' + prompt)
        hs = []
        space = '       '
        arrow = term.text.bold_green('    => ')
        cur = default
        for i, opt in enumerate(opts):
            h = term.output(arrow if i == cur else space, frozen = False)
            num = numfmt % (i + 1)
            term.output(num)
            term.output(opt + '\n', indent = len(num) + len(space))
            hs.append(h)
        ds = ''
        while True:
            prev = cur
            was_digit = False
            k = term.key.get()
            if   k == '<up>':
                if cur is None:
                    cur = 0
                else:
                    cur = max(0, cur - 1)
            elif k == '<down>':
                if cur is None:
                    cur = 0
                else:
                    cur = min(len(opts) - 1, cur + 1)
            elif k == 'C-<up>':
                cur = 0
            elif k == 'C-<down>':
                cur = len(opts) - 1
            elif k in ('<enter>', '<right>'):
                if cur is not None:
                    return cur

            
            elif k in min(tuple(string.digits), tuple(map(str, range(len(opts) + 1))), key=len):
                was_digit = True
                d = str(k)
                n = int(ds + d)
                if 0 < n <= len(opts):
                    ds += d
                    cur = n - 1
                elif d != '0':
                    ds = d
                    n = int(ds)
                    cur = n - 1

            if prev != cur:
                if prev is not None:
                    hs[prev].update(space)
                if was_digit:
                    hs[cur].update(term.text.bold_green('%5s> ' % ds))
                else:
                    hs[cur].update(arrow)
    else:
        linefmt =       '       %' + str(len(str(len(opts)))) + 'd) %s'
        if default is not None:
            default += 1
        while True:
            print(' [?] ' + prompt)
            for i, opt in enumerate(opts):
                print(linefmt % (i + 1, opt))
            s = '     Choice '
            if default:
                s += '[%s] ' % str(default)
            try:
                x = int(raw_input(s) or default)
            except (ValueError, TypeError):
                continue
            if x >= 1 and x <= len(opts):
                return x - 1