module PEdump::Colors
  def gray(str)
    "\e[1;30m#{str}\e[0m"
  end

  def red(str)
    "\e[1;31m#{str}\e[0m"
  end

  def green(str)
    "\e[1;32m#{str}\e[0m"
  end

  def yellow(str)
    "\e[1;33m#{str}\e[0m"
  end

  def redish(str)
    "\e[0;31m#{str}\e[0m"
  end

  def greenish(str)
    "\e[0;32m#{str}\e[0m"
  end

  def yellowish(str)
    "\e[0;33m#{str}\e[0m"
  end
end
